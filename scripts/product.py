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
import shutil
import signal
import subprocess
import sys
import tarfile
import time
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


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def build(args):
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


def configure(args):
    """Register only the real adapter; compile only the checked-in owned fixture."""
    python = ROOT / ".venv/bin/python"
    if not python.is_file():
        raise ValueError("Run sh scripts/setup-python.sh first")
    plugin = args.workspace / "shield-build/AegisShield.so"
    if not plugin.is_file():
        raise ValueError("Shield plugin missing; run the build command first")
    args.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = args.workspace / "aegis.toml"
    if config.exists():
        raise ValueError(f"Refusing to overwrite {config}; reuse it or choose a new workspace")
    command = [str(python), str(ROOT / "protectors/llvm/adapter/aegis_llvm_adapter.py"),
               "--opt", tool("opt"), "--plugin", str(plugin)]
    text = (f"[storage]\nroot = {json.dumps(str(args.workspace / 'store'))}\n"
            "max_input_bytes = 67108864\n[attack_lab]\nenabled = false\n"
            f"[adapters.llvm-shield]\ncommand = {json.dumps(command)}\n"
            'tasks = ["protect"]\ntimeout_seconds = 300\nenv_passthrough = []\nmax_stdout_bytes = 65536\n')
    run([tool("clang"), "-O1", "-S", "-emit-llvm", "protectors/llvm/tests/fixtures/annotated.c",
         "-o", args.workspace / "annotated.ll"])
    with config.open("x") as stream:
        os.chmod(config, 0o600)
        stream.write(text)
    print(f"Configured {config}; owned fixture: {args.workspace / 'annotated.ll'}")


def serve(args):
    config = args.workspace / "aegis.toml"
    if not config.is_file() or not (DASHBOARD / "dist/index.html").is_file():
        raise ValueError("Run build and configure before serve")
    # Fail before spawning if an unrelated service already owns either port.
    import socket
    for port in (8000, 5173):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
    env = {**os.environ, "AEGIS_CONFIG": str(config)}
    children = []
    def shutdown(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        children.append(subprocess.Popen([str(ROOT / ".venv/bin/python"), "-m", "aegis_api"],
                                         cwd=ROOT, env=env, start_new_session=True))
        deadline = time.monotonic() + 15
        while True:
            if children[0].poll() is not None:
                raise ValueError("API exited during startup")
            try:
                direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with direct.open("http://127.0.0.1:8000/healthz", timeout=1) as response:
                    if json.load(response)["status"] == "ok":
                        break
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise ValueError("API did not become healthy within 15 seconds")
            time.sleep(0.2)
        children.append(subprocess.Popen([tool("npm"), "run", "preview", "--", "--host", "127.0.0.1",
                                          "--port", "5173", "--strictPort"],
                                         cwd=DASHBOARD, start_new_session=True))
        print("Dashboard: http://127.0.0.1:5173 | API: http://127.0.0.1:8000", flush=True)
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
    base = "http://127.0.0.1:5173"
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
    health = request("/healthz")
    if not any(b["name"] == "llvm-shield" and b["available"] for b in health["backends"]):
        raise ValueError("Real llvm-shield backend is not registered/available")
    fixture = args.workspace / "annotated.ll"
    job = request("/v1/jobs", {"policy": {"backend": "llvm-shield", "options": {"seed": "42"}},
                             "input": {"name": fixture.name, "content_base64": base64.b64encode(fixture.read_bytes()).decode()}})
    deadline = time.monotonic() + 310
    while job["status"] in ("pending", "running"):
        if time.monotonic() > deadline:
            raise ValueError("Submitted job did not reach a terminal state in 310 seconds")
        time.sleep(0.2)
        job = request(f"/v1/jobs/{job['job_id']}")
    report = request(f"/v1/jobs/{job['job_id']}/report")
    if job["status"] != "succeeded" or report["status"] != "succeeded":
        raise ValueError(f"Real job failed: {job.get('error')}")
    if not any(e["source"] == "adapter" and e["data"].get("transformed_sites", 0) > 0 for e in report["evidence"]):
        raise ValueError("Report lacks a nonzero transformation claim")
    # Independently reload every local output and compare Core's recorded digest.
    for artifact in report["output_artifacts"]:
        path = args.workspace / "store" / artifact["storage_path"]
        if digest(path) != artifact["sha256"]:
            raise ValueError("Output artifact digest mismatch")
    print(json.dumps({"job_id": job["job_id"], "status": job["status"],
                      "output_sha256": [a["sha256"] for a in report["output_artifacts"]]}))


def package(args):
    """Build a reviewable source + dashboard archive, never runtime/private evidence."""
    if not (DASHBOARD / "dist/index.html").is_file():
        raise ValueError("Build the dashboard before packaging")
    args.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = args.workspace / "aegis-local-review.tar.gz"
    files = subprocess.check_output(["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    # Untracked files are restricted to the product delivery paths.
    tracked = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0"))
    files = [p for p in files if p and (p in tracked or p.startswith(("scripts/", "docs/release/", "platform/dashboard/")))]
    files += [str(p.relative_to(ROOT)) for p in (DASHBOARD / "dist").rglob("*") if p.is_file()]
    inventory = {}
    for name in sorted(set(files)):
        path = ROOT / name
        if any(part in {".git", ".venv", "node_modules", "test-results", "playwright-report", ".agents", ".codex"}
               or part.startswith(".env") for part in path.relative_to(ROOT).parts):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Nonregular source file: {name}")
        inventory[name] = digest(path)
    manifest = {"schema": "aegis.local-release.v1", "license_status": "pending_owner_review",
                "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "files_sha256": inventory, "note": "Inventory binds working-tree bytes, including uncommitted product changes."}
    with target.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w|") as archive:
        for name in [*inventory, "RELEASE-MANIFEST.json"]:
            data = (json.dumps(manifest, indent=2) + "\n").encode() if name == "RELEASE-MANIFEST.json" else (ROOT / name).read_bytes()
            info = tarfile.TarInfo("aegis/" + name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    print(f"{digest(target)}  {target}")


def verify(args):
    """Required product suites. Missing prerequisites fail, never skip the suite."""
    python = ROOT / ".venv/bin/python"
    plugin = args.workspace / "shield-build/AegisShield.so"
    if not plugin.is_file() or not (args.workspace / "aegis.toml").is_file():
        raise ValueError("Run build and configure before verify")
    run([python, "-m", "pytest", "core/tests", "platform/api/tests", "platform/cli/tests",
         "provenance/tests", "sentinel/tests", "protectors/llvm/adapter/tests", "scripts/tests", "-q",
         "--shield-plugin", plugin, "--shield-opt", tool("opt"), "--shield-clang", tool("clang")])
    run(["ctest", "--test-dir", args.workspace / "shield-build", "--output-on-failure"])
    run(["ctest", "--test-dir", args.workspace / "imagelab-build", "--output-on-failure"])
    run([python, "-m", "pytest", "protectors/mirage/tests", "-q"])
    run([python, "-m", "pytest", "scripts/native_tests", "-q"])
    run([python, "-m", "pytest", "attack_lab/tests", "--lab-profile", "offline", "-q"])
    run(["npm", "--prefix", DASHBOARD, "test"])
    run(["npm", "--prefix", DASHBOARD, "run", "test:e2e"],
        env={**os.environ, "AEGIS_PRODUCT_WORKSPACE": str(args.workspace)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "configure", "serve", "smoke", "verify", "package"))
    parser.add_argument("--workspace", type=Path, default=Path(os.environ.get("AEGIS_PRODUCT_WORKSPACE", "/tmp/aegis-product")))
    args = parser.parse_args()
    args.workspace = args.workspace.resolve()
    if args.workspace.is_relative_to(ROOT):
        parser.error("Use a workspace outside the source tree (for example /tmp/aegis-product)")
    try:
        globals()[args.command](args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
