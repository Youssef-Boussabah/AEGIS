#!/usr/bin/env python3
"""Local product build/configuration/server/package. No package installation or deployment."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "platform/dashboard"


def run(argv, **kwargs):
    print("+", " ".join(map(str, argv)), flush=True)
    return subprocess.run(list(map(str, argv)), cwd=ROOT, check=True, timeout=600, **kwargs)


def tool(name):
    path = shutil.which(name)
    if not path:
        raise ValueError(f"Required tool unavailable: {name}; install it explicitly first")
    return str(Path(path).absolute())


def port(value):
    """Loopback TCP port for a local service; privileged ports are refused."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {value!r}") from None
    if not 1024 <= number <= 65535:
        raise argparse.ArgumentTypeError(f"port must be between 1024 and 65535: {value}")
    return number


def read_health(url, timeout=1):
    """Return the API health body. A degraded API answers 503 with a valid report body."""
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with direct.open(url, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code != 503:
            raise
        with exc:
            body = json.load(exc)
        if not isinstance(body, dict) or body.get("status") != "degraded":
            raise ValueError(f"Unexpected HTTP 503 from {url}") from None
        return body


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def private_workspace(path):
    """Create a new workspace as 0700. Existing directories are never chmodded, only flagged."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_mode & 0o077:
        print(f"warning: {path} is accessible to other local users; it will hold private job inputs "
              f"and reports. Consider: chmod 700 {path}", file=sys.stderr, flush=True)


def check_build_source(build_dir, source):
    """Refuse a native build configured from another (possibly deleted) checkout."""
    cache = Path(build_dir) / "CMakeCache.txt"
    if not cache.is_file():
        return
    for line in cache.read_text(errors="replace").splitlines():
        if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL="):
            recorded = Path(line.split("=", 1)[1])
            if recorded.resolve() != (ROOT / source).resolve():
                raise ValueError(f"{build_dir} was configured from {recorded}, not this checkout; "
                                 "use a new --workspace and run build/configure again")
            return


def check_config_paths(config):
    """Every absolute path in a registered adapter command must exist (health checks only argv[0])."""
    import tomllib
    with config.open("rb") as stream:
        adapters = tomllib.load(stream).get("adapters", {})
    missing = [arg for spec in adapters.values() for arg in spec.get("command", [])
               if isinstance(arg, str) and arg.startswith("/") and not Path(arg).exists()]
    if missing:
        raise ValueError(f"{config} references missing paths: {', '.join(missing)}; "
                         "use a new --workspace and run build/configure again")


def build(args):
    private_workspace(args.workspace)
    check_build_source(args.workspace / "shield-build", "protectors/llvm")
    check_build_source(args.workspace / "imagelab-build", "demo/image_processor")
    llvm_dir = subprocess.check_output([tool("llvm-config"), "--cmakedir"], text=True).strip()
    if not subprocess.check_output([tool("llvm-config"), "--version"], text=True).startswith("22."):
        raise ValueError("This release requires matching LLVM/Clang 22 tools on PATH")
    plugin_build = args.workspace / "shield-build"
    run(["cmake", "-S", "protectors/llvm", "-B", plugin_build, "-G", "Ninja",
         f"-DLLVM_DIR={llvm_dir}", f"-DCMAKE_CXX_COMPILER={tool('clang++')}", "-DCMAKE_BUILD_TYPE=Release"])
    run(["cmake", "--build", plugin_build, "-j2"])
    run(["cmake", "-S", "demo/image_processor", "-B", args.workspace / "imagelab-build", "-G", "Ninja",
         f"-DCMAKE_CXX_COMPILER={tool('clang++')}", "-DCMAKE_BUILD_TYPE=Release",
         f"-DIMAGELAB_SHIELD_PLUGIN={plugin_build / 'AegisShield.so'}"])
    run(["cmake", "--build", args.workspace / "imagelab-build", "-j2"])
    run(["npm", "--prefix", DASHBOARD, "run", "build"])


ADAPTERS = ROOT / "protectors/llvm/adapter"
MIRAGE_BACKEND = "llvm-shield-mirage"


def adapter_commands(python, plugin):
    """Operator-trusted argv for each supported backend; every path absolute."""
    shield = [str(python), str(ADAPTERS / "aegis_llvm_adapter.py"), "--opt", tool("opt"), "--plugin", str(plugin)]
    combined = [str(python), str(ADAPTERS / "aegis_shield_mirage_adapter.py"), "--opt", tool("opt"),
                "--plugin", str(plugin), "--clang", tool("clang"), "--llvm-link", tool("llvm-link")]
    return {"llvm-shield": shield, MIRAGE_BACKEND: combined}


def adapter_toml(name, command):
    return (f"[adapters.{name}]\ncommand = {json.dumps(command)}\n"
            'tasks = ["protect"]\ntimeout_seconds = 300\nenv_passthrough = []\nmax_stdout_bytes = 65536\n')


def probe_backend(python, workspace, name, command, fixture):
    """Run one real job on the owned fixture through Core's CLI in a throwaway store.

    Returns None on a verified success, else a short failure description.
    """
    import tempfile
    with tempfile.TemporaryDirectory(prefix=f"probe-{name}-", dir=workspace) as scratch:
        config = Path(scratch) / "aegis.toml"
        config.write_text(f"[storage]\nroot = {json.dumps(str(Path(scratch) / 'store'))}\n"
                          "[attack_lab]\nenabled = false\n" + adapter_toml(name, command))
        proc = subprocess.run([str(python), "-m", "aegis_cli", "protect", "--config", str(config), "--json",
                               "--backend", name, "--option", 'seed="42"', str(fixture)],
                              cwd=ROOT, capture_output=True, text=True, timeout=330)
        try:
            job = json.loads(proc.stdout)
        except ValueError:
            return f"CLI exit {proc.returncode} without a job record"
        if job.get("status") != "succeeded":
            error = job.get("error") or {}
            adapter = (error.get("details") or {}).get("adapter_error") or {}
            return f"{error.get('code')}/{adapter.get('code')}: {adapter.get('message') or error.get('message')}"
        names = {a["name"]: a for a in job.get("output_artifacts", [])}
        if name == MIRAGE_BACKEND:
            try:
                report = json.loads((Path(scratch) / "store" / names["mirage-report.json"]["storage_path"]).read_bytes())
            except (KeyError, OSError, ValueError):
                return "succeeded without a readable mirage-report.json"
            if (report.get("inserted_count", 0) < 1
                    or report.get("input_sha256") != names.get("shield-stage.ll", {}).get("sha256")
                    or report.get("output_sha256") != names.get("protected.ll", {}).get("sha256")):
                return "Mirage report does not bind Core's shield-stage.ll and protected.ll hashes"
        elif "protected.ll" not in names:
            return "succeeded without protected.ll"
    return None


def configure(args):
    """Register only adapters whose real probe job succeeds; compile only the owned fixture."""
    python = ROOT / ".venv/bin/python"
    if not python.is_file():
        raise ValueError("Run sh scripts/setup-python.sh first")
    plugin = args.workspace / "shield-build/AegisShield.so"
    if not plugin.is_file():
        raise ValueError("Shield plugin missing; run the build command first")
    private_workspace(args.workspace)
    config = args.workspace / "aegis.toml"
    if config.exists():
        raise ValueError(f"Refusing to overwrite {config}; reuse it or choose a new workspace")
    # Core creates job directories with the process umask; keep the store root private.
    (args.workspace / "store").mkdir(mode=0o700, exist_ok=True)
    fixture = args.workspace / "annotated.ll"
    run([tool("clang"), "-O1", "-S", "-emit-llvm", "protectors/llvm/tests/fixtures/annotated.c", "-o", fixture])
    registered = []
    for name, command in adapter_commands(python, plugin).items():
        problem = probe_backend(python, args.workspace, name, command, fixture)
        if problem is None:
            registered.append((name, command))
            print(f"Probe passed: {name} (owned fixture, seed 42)", flush=True)
        elif name == "llvm-shield":
            raise ValueError(f"llvm-shield probe failed ({problem}); no config written")
        else:
            print(f"warning: {name} NOT registered; its probe failed: {problem}", file=sys.stderr, flush=True)
    text = (f"# Generated by scripts/product.py configure. Registered backends passed a real probe job.\n"
            f"[storage]\nroot = {json.dumps(str(args.workspace / 'store'))}\n"
            "max_input_bytes = 67108864\n[attack_lab]\nenabled = false\n"
            + "".join(adapter_toml(name, command) for name, command in registered))
    with config.open("x") as stream:
        os.chmod(config, 0o600)
        stream.write(text)
    print(f"Configured {config} with {', '.join(name for name, _ in registered)}; owned fixture: {fixture}")


def serve(args):
    config = args.workspace / "aegis.toml"
    if not config.is_file() or not (DASHBOARD / "dist/index.html").is_file():
        raise ValueError("Run build and configure before serve")
    check_config_paths(config)
    api_port, dashboard_port = args.api_port, args.dashboard_port
    if api_port == dashboard_port:
        raise ValueError("API and dashboard ports must differ")
    # Fail before spawning if an unrelated service already owns either port.
    import socket
    for number in (api_port, dashboard_port):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", number))
            except OSError as exc:
                raise ValueError(f"127.0.0.1:{number} is already in use ({exc.strerror}); stop that "
                                 "service or choose --api-port/--dashboard-port") from None
    # The dashboard proxy reads AEGIS_API_PORT (vite.config.ts).
    env = {**os.environ, "AEGIS_CONFIG": str(config), "AEGIS_API_PORT": str(api_port)}
    children = []
    def shutdown(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    # The children run in their own sessions and never see a terminal hangup; without
    # this, closing the terminal leaves the token-gated API and dashboard running.
    signal.signal(signal.SIGHUP, shutdown)
    try:
        children.append(subprocess.Popen([str(ROOT / ".venv/bin/python"), "-m", "aegis_api",
                                          "--port", str(api_port)],
                                         cwd=ROOT, env=env, start_new_session=True))
        deadline = time.monotonic() + 15
        while True:
            if children[0].poll() is not None:
                raise ValueError("API exited during startup")
            try:
                health = read_health(f"http://127.0.0.1:{api_port}/healthz")
                if health["status"] == "ok":
                    break
                # Degraded health will not recover by waiting; jobs would only fail.
                raise ValueError("API health is degraded: " + "; ".join(map(str, health.get("problems", []))))
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise ValueError("API did not become healthy within 15 seconds")
            time.sleep(0.2)
        children.append(subprocess.Popen([tool("npm"), "run", "preview", "--", "--host", "127.0.0.1",
                                          "--port", str(dashboard_port), "--strictPort"],
                                         cwd=DASHBOARD, env=env, start_new_session=True))
        # Announce the URL only once the preview answers and its proxy reaches this API.
        deadline = time.monotonic() + 15
        while True:
            if children[1].poll() is not None:
                raise ValueError("Dashboard preview exited during startup")
            try:
                if read_health(f"http://127.0.0.1:{dashboard_port}/healthz")["status"] == "ok":
                    break
            except (OSError, ValueError):
                pass
            if time.monotonic() > deadline:
                raise ValueError("Dashboard preview did not proxy API health within 15 seconds")
            time.sleep(0.2)
        print(f"Dashboard: http://127.0.0.1:{dashboard_port} | API: http://127.0.0.1:{api_port}", flush=True)
        while True:
            for child in children:
                if child.poll() is not None:
                    raise ValueError(f"Local service exited with code {child.returncode}")
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()


def smoke(args):
    """HTTP smoke through the dashboard proxy; browser suite covers rendering separately."""
    base = f"http://127.0.0.1:{args.dashboard_port}"
    token = os.environ.get("AEGIS_API_TOKEN")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    def request(path, payload=None):
        req = urllib.request.Request(base + path, headers=headers,
                                     data=None if payload is None else json.dumps(payload).encode())
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct.open(req, timeout=10) as response:
            return json.load(response)
    health = read_health(base + "/healthz", timeout=10)
    if health["status"] != "ok":
        raise ValueError("API health is degraded: " + "; ".join(map(str, health.get("problems", []))))
    available = {b["name"] for b in health["backends"] if b["available"] and "protect" in b["tasks"]}
    if "llvm-shield" not in available:
        raise ValueError("Real llvm-shield backend is not registered/available")
    fixture = args.workspace / "annotated.ll"
    results = []
    for backend in [name for name in ("llvm-shield", MIRAGE_BACKEND) if name in available]:
        job = request("/v1/jobs", {"policy": {"backend": backend, "options": {"seed": "42"}},
                                 "input": {"name": fixture.name,
                                           "content_base64": base64.b64encode(fixture.read_bytes()).decode()}})
        deadline = time.monotonic() + 310
        while job["status"] in ("pending", "running"):
            if time.monotonic() > deadline:
                raise ValueError(f"{backend} job did not reach a terminal state in 310 seconds")
            time.sleep(0.2)
            job = request(f"/v1/jobs/{job['job_id']}")
        report = request(f"/v1/jobs/{job['job_id']}/report")
        if job["status"] != "succeeded" or report["status"] != "succeeded":
            raise ValueError(f"Real {backend} job failed: {job.get('error')}")
        if not any(e["source"] == "adapter" and e["data"].get("transformed_sites", 0) > 0 for e in report["evidence"]):
            raise ValueError(f"{backend} report lacks a nonzero transformation claim")
        # Independently reload every local output and compare Core's recorded digest.
        artifacts = {a["name"]: a for a in report["output_artifacts"]}
        for artifact in artifacts.values():
            path = args.workspace / "store" / artifact["storage_path"]
            if digest(path) != artifact["sha256"]:
                raise ValueError("Output artifact digest mismatch")
        if backend == MIRAGE_BACKEND:
            mirage = json.loads((args.workspace / "store" / artifacts["mirage-report.json"]["storage_path"]).read_bytes())
            if (mirage["inserted_count"] < 1 or mirage["input_sha256"] != artifacts["shield-stage.ll"]["sha256"]
                    or mirage["output_sha256"] != artifacts["protected.ll"]["sha256"]):
                raise ValueError("Shield+Mirage chain does not match Core's recorded hashes")
        results.append({"backend": backend, "job_id": job["job_id"], "status": job["status"],
                        "output_sha256": [a["sha256"] for a in report["output_artifacts"]]})
    # Top-level fields keep the original llvm-shield shape; every backend run is listed.
    print(json.dumps({**results[0], "backends": results}))


def package_excluded(name):
    """Release boundary; synthetic checked-in test inputs remain distributable."""
    parts = PurePosixPath(name).parts
    checked_parts = parts[3:] if parts[:3] == ("platform", "dashboard", "dist") else parts
    if any(part in {".git", ".venv", "venv", "node_modules", "test-results", "playwright-report",
                    ".agents", ".codex", ".aws", "__pycache__", ".pytest_cache", ".aegis",
                    "store", "private-evidence", "private-plan", ".inference-uses", "approvals",
                    "CMakeFiles", "build", "dist"} for part in checked_parts):
        return True
    leaf = parts[-1]
    if any(part.startswith(".env") and part != ".env.example" for part in parts):
        return True
    return (leaf in {"aegis.toml", "credentials", "credentials.json", "RELEASE-MANIFEST.json", "CMakeCache.txt",
                     "experiment.json", "ghidra-analysis.json", "shield-report.json", "mirage-report.json"}
            or leaf.startswith(("approval.", "approval-")) or leaf == "approval.json"
            or leaf.endswith((".pyc", ".pyo", ".tsbuildinfo", ".log", ".so", ".o", ".a", ".tar.gz", ".zip")))


def package(args):
    """Build a reviewable source + dashboard archive, never runtime/private evidence."""
    if not (DASHBOARD / "dist/index.html").is_file():
        raise ValueError("Build the dashboard before packaging")
    private_workspace(args.workspace)
    target = args.workspace / "aegis-local-review.tar.gz"
    # Tracked plus untracked, non-ignored files: the release is the working tree, and new
    # source files anywhere (adapters, Lab, Provenance) must ship with the code using them.
    files = subprocess.check_output(["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    files = [p for p in files if p]
    files += [str(p.relative_to(ROOT)) for p in (DASHBOARD / "dist").rglob("*") if p.is_file()]
    inventory, contents, modes = {}, {}, {}
    for name in sorted(set(files)):
        path = ROOT / name
        if package_excluded(name):
            continue
        # Never ship key material, even if someone left it untracked and unignored.
        if path.suffix in {".pem", ".key", ".p12", ".pfx"} or path.name.startswith(("id_rsa", "id_ed25519")):
            raise ValueError(f"Refusing to package key-like file {name}; move it outside the source tree")
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError(f"Nonregular source file: {name}")
        data = path.read_bytes()
        # Reject real PEM payloads even under an unexpected extension. Test source
        # strings mentioning PEM headers do not contain a complete PEM payload.
        if re.search(rb"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----\s+[A-Za-z0-9+/=\r\n]{40,}-----END", data):
            raise ValueError(f"Refusing to package private key content: {name}")
        if path.suffix == ".json":
            try:
                value = json.loads(data)
            except (ValueError, UnicodeError):
                value = None  # Malformed synthetic fixtures are valid test inputs.
            if isinstance(value, dict) and ("operator_approved" in value or "provider_retention_reviewed" in value):
                raise ValueError(f"Refusing to package inference approval content: {name}")
        contents[name] = data
        modes[name] = 0o755 if path.stat().st_mode & 0o111 else 0o644
        inventory[name] = hashlib.sha256(data).hexdigest()
    manifest = {"schema": "aegis.local-release.v1", "license_status": "approved", "license": "MIT",
                "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "files_sha256": inventory, "note": "Inventory binds working-tree bytes, including uncommitted product changes."}
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w|") as archive:
        for name in [*inventory, "RELEASE-MANIFEST.json"]:
            data = (json.dumps(manifest, indent=2) + "\n").encode() if name == "RELEASE-MANIFEST.json" else contents[name]
            info = tarfile.TarInfo("aegis/" + name)
            info.size = len(data)
            info.mode = modes.get(name, 0o644)
            archive.addfile(info, io.BytesIO(data))
    print(f"{digest(target)}  {target}")


def check_package(args):
    """Verify an untouched extracted package before installing local dependencies.

    Integrity against this inventory is not publisher authentication. Compare the
    archive digest with the separately delivered operator-reviewed digest first.
    """
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate package inventory key")
            result[key] = value
        return result
    manifest_path = ROOT / "RELEASE-MANIFEST.json"
    if manifest_path.is_symlink():
        raise ValueError("Symlink package manifest")
    manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=unique)
    if (not isinstance(manifest, dict) or manifest.get("schema") != "aegis.local-release.v1"
            or not isinstance(manifest.get("files_sha256"), dict) or not manifest["files_sha256"]):
        raise ValueError("Unsupported package inventory")
    inventory = manifest["files_sha256"]
    for name, expected in inventory.items():
        parts = PurePosixPath(name).parts
        if (not parts or PurePosixPath(name).is_absolute() or ".." in parts or "\\" in name
                or str(PurePosixPath(name)) != name or name == "RELEASE-MANIFEST.json"
                or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("Unsafe package inventory entry")
        path = ROOT / name
        if any((ROOT.joinpath(*parts[:i])).is_symlink() for i in range(1, len(parts) + 1)):
            raise ValueError(f"Symlink inventory entry: {name}")
        if not path.is_file() or digest(path) != expected:
            raise ValueError(f"Missing or changed package file: {name}")
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if not p.is_dir() or p.is_symlink()}
    if actual != set(inventory) | {"RELEASE-MANIFEST.json"}:
        raise ValueError("Package has unlisted or missing files; check before installation")
    print(f"Verified {len(inventory)} file digests; no extra files; license={manifest.get('license_status')}")


def verify(args):
    """Required product suites. Missing prerequisites fail, never skip the suite."""
    python = ROOT / ".venv/bin/python"
    plugin = args.workspace / "shield-build/AegisShield.so"
    if not plugin.is_file() or not (args.workspace / "aegis.toml").is_file():
        raise ValueError("Run build and configure before verify")
    check_build_source(args.workspace / "shield-build", "protectors/llvm")
    check_build_source(args.workspace / "imagelab-build", "demo/image_processor")
    check_config_paths(args.workspace / "aegis.toml")
    run([python, "-m", "pytest", "core/tests", "platform/api/tests", "platform/cli/tests",
         "provenance/tests", "sentinel/tests", "protectors/llvm/adapter/tests", "scripts/tests", "-q",
         "--shield-plugin", plugin, "--shield-opt", tool("opt"), "--shield-clang", tool("clang"),
         "--shield-llvm-link", tool("llvm-link")])
    run(["ctest", "--test-dir", args.workspace / "shield-build", "--output-on-failure"])
    run(["ctest", "--test-dir", args.workspace / "imagelab-build", "--output-on-failure"])
    run([python, "-m", "pytest", "protectors/mirage/tests", "-q"])
    run([python, "-m", "pytest", "scripts/native_tests", "-q", "--shield-plugin", plugin])
    run([python, "-m", "pytest", "attack_lab/tests", "--lab-profile", getattr(args, "lab_profile", "offline"), "-q"])
    run(["npm", "--prefix", DASHBOARD, "test"])
    # The browser suite serves dist/; rebuild so it never exercises a stale bundle.
    run(["npm", "--prefix", DASHBOARD, "run", "build"])
    run(["npm", "--prefix", DASHBOARD, "run", "test:e2e"],
        env={**os.environ, "AEGIS_PRODUCT_WORKSPACE": str(args.workspace),
             "AEGIS_API_PORT": str(args.api_port), "AEGIS_DASHBOARD_PORT": str(args.dashboard_port)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "configure", "serve", "smoke", "verify", "package", "check-package"))
    parser.add_argument("--lab-profile", choices=("offline", "integration"), default="offline",
                        help="Use integration for the final gate; requires AEGIS_GHIDRA_HEADLESS and refuses skips")
    parser.add_argument("--workspace", type=Path, default=Path(os.environ.get("AEGIS_PRODUCT_WORKSPACE", "/tmp/aegis-product")))
    parser.add_argument("--api-port", type=port, default=os.environ.get("AEGIS_API_PORT", "8000"),
                        help="loopback API port (default: $AEGIS_API_PORT or 8000)")
    parser.add_argument("--dashboard-port", type=port, default=os.environ.get("AEGIS_DASHBOARD_PORT", "5173"),
                        help="loopback dashboard port (default: $AEGIS_DASHBOARD_PORT or 5173)")
    args = parser.parse_args()
    args.workspace = args.workspace.resolve()
    if args.workspace.is_relative_to(ROOT):
        parser.error("Use a workspace outside the source tree (for example /tmp/aegis-product)")
    try:
        globals()[args.command.replace("-", "_")](args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
