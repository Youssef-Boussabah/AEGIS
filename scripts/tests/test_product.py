"""Product tooling checks: no candidate execution or fabricated protection evidence."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), ROOT / "scripts" / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


product = module("product.py")
exporter = module("export-product-evidence.py")


def test_configure_requires_real_plugin_and_preserves_existing_config(tmp_path):
    with pytest.raises(ValueError, match="plugin missing"):
        product.configure(SimpleNamespace(workspace=tmp_path))
    (tmp_path / "shield-build").mkdir()
    (tmp_path / "shield-build/AegisShield.so").write_bytes(b"not executable; existence check only")
    config = tmp_path / "aegis.toml"
    config.write_text("owner config")
    with pytest.raises(ValueError, match="overwrite"):
        product.configure(SimpleNamespace(workspace=tmp_path))
    assert config.read_text() == "owner config"


def test_runtime_workspace_cannot_be_source_tree():
    result = subprocess.run([sys.executable, str(ROOT / "scripts/product.py"), "configure", "--workspace", str(ROOT)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "outside the source tree" in result.stderr


def test_missing_config_is_not_a_fake_server_success(tmp_path):
    with pytest.raises(ValueError, match="build and configure"):
        product.serve(SimpleNamespace(workspace=tmp_path))


def test_mirage_export_verifies_both_artifacts_and_omits_private_fields(tmp_path):
    original = tmp_path / "original.ll"
    original.write_bytes(b"unit-test IR, never executed")
    transformed = tmp_path / "module.ll"
    transformed.write_bytes(b"unit-test changed IR, never executed")
    report = {"schema_version": "aegis.mirage.report.v1", "input_sha256": exporter.sha(original),
              "output_sha256": exporter.sha(transformed), "inserted_count": 1, "inserted_functions": ["private_function_name"],
              "request": "PRIVATE_REQUEST_MARKER"}
    (tmp_path / "report.json").write_text(json.dumps(report))
    _, summary = exporter.mirage(tmp_path, original)
    assert summary["inserted_count"] == 1
    assert summary["security_property"] == "not_established"
    assert "PRIVATE" not in json.dumps(summary) and "private_function_name" not in json.dumps(summary)
    transformed.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="digest mismatch"):
        exporter.mirage(tmp_path, original)


def test_export_errors_do_not_echo_private_json(tmp_path):
    (tmp_path / "report.json").write_text('{"private":"PRIVATE_REQUEST_MARKER"}')
    result = subprocess.run([sys.executable, str(ROOT / "scripts/export-product-evidence.py"), "mirage", str(tmp_path),
                             "--original-ir", str(tmp_path / "absent"), "--output", str(tmp_path / "out.json")],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert "PRIVATE_REQUEST_MARKER" not in result.stdout + result.stderr
    assert not (tmp_path / "out.json").exists()


def test_benchmark_missing_artifact_fails_export(tmp_path):
    path = tmp_path / "compare.json"
    path.write_text(json.dumps({"schema": "imagelab.compare.v1", "artifacts": {"shield": {"cli": {"missing": True}}}}))
    with pytest.raises(ValueError, match="missing artifact"):
        exporter.benchmark(path)


def test_package_includes_built_dashboard_and_inventory_but_never_secrets(tmp_path, monkeypatch):
    root = tmp_path / "source"
    dashboard = root / "platform/dashboard"
    (dashboard / "dist").mkdir(parents=True)
    (dashboard / "dist/index.html").write_text("built dashboard fixture")
    (root / "README.md").write_text("public readme fixture")
    (root / ".env").write_text("PRIVATE_MARKER")
    (root / "scripts").mkdir()
    (root / "scripts/product.py").write_text("public script fixture")
    monkeypatch.setattr(product, "ROOT", root)
    monkeypatch.setattr(product, "DASHBOARD", dashboard)
    def git(argv, **kwargs):
        if "rev-parse" in argv:
            return "a" * 40
        return b"README.md\0.env\0scripts/product.py\0"
    monkeypatch.setattr(product.subprocess, "check_output", git)
    args = SimpleNamespace(workspace=tmp_path / "package-1")
    product.package(args)
    archive = args.workspace / "aegis-local-review.tar.gz"
    with tarfile.open(archive) as tar:
        names = tar.getnames()
        assert "aegis/.env" not in names
        assert "aegis/platform/dashboard/dist/index.html" in names
        manifest = json.load(tar.extractfile("aegis/RELEASE-MANIFEST.json"))
        assert manifest["license_status"] == "approved"
        assert manifest["license"] == "MIT"
        for name, expected in manifest["files_sha256"].items():
            import hashlib
            assert hashlib.sha256(tar.extractfile("aegis/" + name).read()).hexdigest() == expected
        assert "PRIVATE_MARKER" not in str(manifest)
    with pytest.raises(FileExistsError):
        product.package(args)
    product.package(SimpleNamespace(workspace=tmp_path / "package-2"))
    assert archive.read_bytes() == (tmp_path / "package-2/aegis-local-review.tar.gz").read_bytes()


def free_port():
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def serve_args(workspace, api_port, dashboard_port):
    return SimpleNamespace(workspace=workspace, api_port=api_port, dashboard_port=dashboard_port)


def test_ports_are_validated_and_default_to_documented_values(monkeypatch):
    import argparse
    assert product.port("8100") == 8100
    for bad in ("80", "70000", "eighty"):
        with pytest.raises(argparse.ArgumentTypeError):
            product.port(bad)
    result = subprocess.run([sys.executable, str(ROOT / "scripts/product.py"), "smoke", "--api-port", "22"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and "between 1024 and 65535" in result.stderr


def test_serve_reports_an_occupied_port_instead_of_a_traceback(tmp_path):
    import socket
    (tmp_path / "aegis.toml").write_text("# empty valid config; serve must stop at the port check\n")
    with socket.socket() as owner:
        owner.bind(("127.0.0.1", 0))
        owner.listen()
        busy = owner.getsockname()[1]
        with pytest.raises(ValueError, match=f"127.0.0.1:{busy} is already in use"):
            product.serve(serve_args(tmp_path, busy, free_port()))
    with pytest.raises(ValueError, match="must differ"):
        product.serve(serve_args(tmp_path, 8100, 8100))


@pytest.mark.skipif(not (ROOT / "platform/dashboard/dist/index.html").is_file(), reason="dashboard not built")
def test_serve_fails_fast_with_degraded_health_problems(tmp_path):
    # A real API process with an adapter whose executable is missing answers 503/degraded.
    (tmp_path / "aegis.toml").write_text(
        f'[storage]\nroot = {json.dumps(str(tmp_path / "store"))}\n'
        '[adapters.llvm-shield]\ncommand = ["aegis-test-adapter-not-on-path"]\ntasks = ["protect"]\n')
    import time
    started = time.monotonic()
    with pytest.raises(ValueError, match="degraded: adapter executable for backend 'llvm-shield' is not available"):
        product.serve(serve_args(tmp_path, free_port(), free_port()))
    assert time.monotonic() - started < 14  # not the generic 15-second startup timeout


@pytest.mark.skipif(not (ROOT / "platform/dashboard/dist/index.html").is_file(), reason="dashboard not built")
@pytest.mark.parametrize("signame", ["SIGHUP", "SIGTERM", "SIGINT"])
def test_serve_stops_its_api_and_dashboard_on_hangup_and_termination(tmp_path, signame):
    """Closing the terminal (SIGHUP) must not leave the token-gated API and dashboard running.

    Both children run in their own sessions, so they never see the terminal's hangup;
    serve itself has to stop them.
    """
    import signal
    import socket
    import time
    workspace = tmp_path / "ws"
    workspace.mkdir(mode=0o700)
    (workspace / "aegis.toml").write_text(f'[storage]\nroot = {json.dumps(str(workspace / "store"))}\n')
    api, dashboard = free_port(), free_port()
    serve = subprocess.Popen([sys.executable, str(ROOT / "scripts/product.py"), "serve", "--workspace",
                              str(workspace), "--api-port", str(api), "--dashboard-port", str(dashboard)],
                             cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)

    def listening(port):
        with socket.socket() as probe:
            return probe.connect_ex(("127.0.0.1", port)) == 0

    try:
        deadline = time.monotonic() + 40
        while not (listening(api) and listening(dashboard)):
            assert serve.poll() is None, serve.stdout.read()
            assert time.monotonic() < deadline, "serve did not start"
            time.sleep(0.2)
        time.sleep(0.5)  # past the startup health loop, into the steady-state wait
        serve.send_signal(getattr(signal, signame))
        serve.wait(timeout=15)
        deadline = time.monotonic() + 10
        while listening(api) or listening(dashboard):
            assert time.monotonic() < deadline, f"children still listening after {signame}"
            time.sleep(0.2)
    finally:
        if serve.poll() is None:
            os.killpg(serve.pid, signal.SIGKILL)
        for port in (api, dashboard):  # never leave orphans behind, even when the test fails
            out = subprocess.run(["ss", "-ltnpH", f"sport = :{port}"], capture_output=True, text=True).stdout
            for pid in {int(p) for p in __import__("re").findall(r"pid=(\d+)", out)}:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass


def test_read_health_accepts_only_a_degraded_503_body(tmp_path):
    import http.server
    import threading
    bodies = {"/degraded": (503, {"status": "degraded", "problems": ["artifact store is not writable"]}),
              "/other": (503, {"status": "ok"}), "/broken": (500, {"error": {}})}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code, body = bodies[self.path]
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert product.read_health(base + "/degraded")["problems"] == ["artifact store is not writable"]
        with pytest.raises(ValueError, match="Unexpected HTTP 503"):
            product.read_health(base + "/other")
        with pytest.raises(product.urllib.error.HTTPError):
            product.read_health(base + "/broken")
    finally:
        server.shutdown()
        server.server_close()


def test_private_workspace_is_created_0700_and_existing_open_directories_are_flagged(tmp_path, capsys):
    import stat
    fresh = tmp_path / "new" / "workspace"
    product.private_workspace(fresh)
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o700
    assert "warning" not in capsys.readouterr().err
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    product.private_workspace(shared)
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755  # never chmodded behind the operator's back
    assert "accessible to other local users" in capsys.readouterr().err


@pytest.mark.skipif(not (product.shutil.which("clang") and product.shutil.which("opt")), reason="clang/opt unavailable")
def test_configure_keeps_store_and_config_private_and_lab_disabled(tmp_path, monkeypatch):
    import stat
    workspace = tmp_path / "ws"
    (workspace / "shield-build").mkdir(parents=True)
    (workspace / "shield-build/AegisShield.so").write_bytes(b"existence check only; never loaded here")
    # Real probes are covered below with a real plugin; this test checks file privacy only.
    monkeypatch.setattr(product, "probe_backend", lambda *args: None)
    product.configure(SimpleNamespace(workspace=workspace))
    assert stat.S_IMODE((workspace / "store").stat().st_mode) == 0o700
    assert stat.S_IMODE((workspace / "aegis.toml").stat().st_mode) == 0o600
    text = (workspace / "aegis.toml").read_text()
    assert "[attack_lab]\nenabled = false" in text and "fake_adapter" not in text
    assert (workspace / "annotated.ll").read_text().startswith("; ModuleID")


def test_builds_and_configs_from_another_checkout_are_refused(tmp_path):
    build = tmp_path / "shield-build"
    build.mkdir()
    (build / "CMakeCache.txt").write_text("CMAKE_HOME_DIRECTORY:INTERNAL=/deleted/aegis-old/protectors/llvm\n")
    with pytest.raises(ValueError, match="configured from /deleted/aegis-old"):
        product.check_build_source(build, "protectors/llvm")
    (build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={ROOT / 'protectors/llvm'}\n")
    product.check_build_source(build, "protectors/llvm")
    product.check_build_source(tmp_path / "absent-build", "protectors/llvm")
    config = tmp_path / "aegis.toml"
    config.write_text(f'[adapters.llvm-shield]\ncommand = [{json.dumps(sys.executable)}, "/deleted/aegis-old/adapter.py", "--seed-flag"]\n')
    with pytest.raises(ValueError, match="missing paths: /deleted/aegis-old/adapter.py"):
        product.check_config_paths(config)
    with pytest.raises(ValueError, match="missing paths"):
        product.serve(serve_args(tmp_path, free_port(), free_port()))
    config.write_text(f'[adapters.llvm-shield]\ncommand = [{json.dumps(sys.executable)}, "--flag"]\n')
    product.check_config_paths(config)


needs_llvm = pytest.mark.skipif(not all(product.shutil.which(t) for t in ("clang", "opt", "llvm-link")),
                                reason="NOT RUN: LLVM 22 clang/opt/llvm-link unavailable")


@needs_llvm
def test_configure_refuses_when_the_real_shield_probe_fails(tmp_path, capsys):
    workspace = tmp_path / "ws"
    (workspace / "shield-build").mkdir(parents=True)
    (workspace / "shield-build/AegisShield.so").write_bytes(b"not a loadable plugin")
    with pytest.raises(ValueError, match="llvm-shield probe failed .*LLVM_FAILED.*no config written"):
        product.configure(SimpleNamespace(workspace=workspace))
    assert not (workspace / "aegis.toml").exists()
    assert not list(workspace.glob("probe-*"))  # throwaway probe stores are removed


def test_optional_backend_is_omitted_with_a_warning_when_its_probe_fails(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "ws"
    (workspace / "shield-build").mkdir(parents=True)
    (workspace / "shield-build/AegisShield.so").write_bytes(b"placeholder")
    monkeypatch.setattr(product, "run", lambda argv, **kw: Path(argv[-1]).write_text("; ModuleID\n"))
    monkeypatch.setattr(product, "tool", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(product, "probe_backend", lambda python, ws, name, command, fixture:
                        None if name == "llvm-shield" else "ADAPTER_FAILED/MIRAGE_FAILED: probe")
    product.configure(SimpleNamespace(workspace=workspace))
    text = (workspace / "aegis.toml").read_text()
    assert "[adapters.llvm-shield]" in text and "llvm-shield-mirage" not in text
    assert "llvm-shield-mirage NOT registered" in capsys.readouterr().err


@needs_llvm
def test_real_probes_register_both_backends(tmp_path, request):
    plugin = request.config.getoption("--shield-plugin", default=None)
    if not plugin or not Path(plugin).is_file():
        pytest.skip("NOT RUN: pass --shield-plugin (scripts/product.py verify does)")
    workspace = tmp_path / "ws"
    (workspace / "shield-build").mkdir(parents=True)
    (workspace / "shield-build/AegisShield.so").symlink_to(Path(plugin).absolute())
    product.configure(SimpleNamespace(workspace=workspace))
    import tomllib
    adapters = tomllib.loads((workspace / "aegis.toml").read_text())["adapters"]
    assert set(adapters) == {"llvm-shield", "llvm-shield-mirage"}
    combined = adapters["llvm-shield-mirage"]["command"]
    assert combined[1].endswith("aegis_shield_mirage_adapter.py") and adapters["llvm-shield-mirage"]["tasks"] == ["protect"]
    assert all(arg.startswith("/") for arg in combined if not arg.startswith("--"))
    product.check_config_paths(workspace / "aegis.toml")
    assert not list(workspace.glob("probe-*"))


def test_package_ships_untracked_source_anywhere_but_refuses_key_files(tmp_path, monkeypatch):
    root = tmp_path / "source"
    dashboard = root / "platform/dashboard"
    (dashboard / "dist").mkdir(parents=True)
    (dashboard / "dist/index.html").write_text("built")
    (root / "protectors/llvm/adapter").mkdir(parents=True)
    (root / "protectors/llvm/adapter/new_adapter.py").write_text("untracked new adapter")
    monkeypatch.setattr(product, "ROOT", root)
    monkeypatch.setattr(product, "DASHBOARD", dashboard)
    listing = [b"protectors/llvm/adapter/new_adapter.py\0"]
    def git(argv, **kwargs):
        return "a" * 40 if "rev-parse" in argv else listing[0]
    monkeypatch.setattr(product.subprocess, "check_output", git)
    product.package(SimpleNamespace(workspace=tmp_path / "ok"))
    with tarfile.open(tmp_path / "ok/aegis-local-review.tar.gz") as tar:
        assert "aegis/protectors/llvm/adapter/new_adapter.py" in tar.getnames()
    (root / "signing.pem").write_text("-----BEGIN PRIVATE KEY-----")
    listing[0] += b"signing.pem\0"
    with pytest.raises(ValueError, match="key-like file signing.pem"):
        product.package(SimpleNamespace(workspace=tmp_path / "refused"))
    assert not (tmp_path / "refused/aegis-local-review.tar.gz").exists()


@pytest.mark.parametrize("name", [
    ".env", ".env.production", "scratch/store/jobs/job.json", "private-evidence/body.json",
    "approvals/request.json", "approval.DRAFT.json", "approval.json", ".inference-uses/reservation.json",
    "aegis.toml", "scratch/output.log", "scratch/data.tar.gz", "platform/dashboard/tsconfig.tsbuildinfo",
    "platform/dashboard/node_modules/module.js", "platform/dashboard/dist/.git/config",
    "scratch/.aws/credentials", "native/AegisShield.so",
    "scratch/experiment.json", "scratch/ghidra-analysis.json", "scratch/shield-report.json", "scratch/mirage-report.json",
])
def test_package_boundary_excludes_private_runtime_and_generated_files(name):
    assert product.package_excluded(name)


@pytest.mark.parametrize("name", [
    ".env.example", "platform/dashboard/dist/assets/index.js", "platform/dashboard/src/research-schema.json",
    "attack_lab/tests/fixtures/public-summary/synthetic-post-hoc.json", "core/guest/aegis-init",
])
def test_package_boundary_preserves_sources_fixtures_and_frontend(name):
    assert not product.package_excluded(name)


@pytest.mark.parametrize("data", [
    b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64 + b"\n-----END PRIVATE KEY-----\n",
    b'{"operator_approved": true, "provider_retention_reviewed": true}',
])
def test_package_refuses_disguised_private_material(tmp_path, monkeypatch, data):
    root = tmp_path / "source"
    dashboard = root / "platform/dashboard"
    (dashboard / "dist").mkdir(parents=True)
    (dashboard / "dist/index.html").write_text("built")
    (root / "innocent.json").write_bytes(data)
    monkeypatch.setattr(product, "ROOT", root)
    monkeypatch.setattr(product, "DASHBOARD", dashboard)
    monkeypatch.setattr(product.subprocess, "check_output", lambda *a, **k: b"innocent.json\0")
    with pytest.raises(ValueError, match="Refusing to package"):
        product.package(SimpleNamespace(workspace=tmp_path / "output"))
    assert not (tmp_path / "output/aegis-local-review.tar.gz").exists()


def extracted_fixture(tmp_path, monkeypatch):
    root = tmp_path / "extracted"
    root.mkdir()
    (root / "README.md").write_text("owned fixture")
    manifest = {"schema": "aegis.local-release.v1", "license_status": "pending_owner_review",
                "files_sha256": {"README.md": product.digest(root / "README.md")}}
    (root / "RELEASE-MANIFEST.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(product, "ROOT", root)
    return root, manifest


def test_extracted_inventory_accepts_exact_package_and_rejects_changed_bytes(tmp_path, monkeypatch):
    root, _ = extracted_fixture(tmp_path, monkeypatch)
    product.check_package(SimpleNamespace())
    (root / "README.md").write_text("changed")
    with pytest.raises(ValueError, match="Missing or changed"):
        product.check_package(SimpleNamespace())


@pytest.mark.parametrize("change", ["extra", "missing", "symlink", "traversal", "duplicate", "fifo"])
def test_extracted_inventory_rejects_unsafe_or_incomplete_packages(tmp_path, monkeypatch, change):
    root, manifest = extracted_fixture(tmp_path, monkeypatch)
    if change == "extra":
        (root / "extra").write_text("unlisted")
    elif change == "missing":
        (root / "README.md").unlink()
    elif change == "symlink":
        source = tmp_path / "outside"
        source.write_text("owned fixture")
        (root / "README.md").unlink()
        (root / "README.md").symlink_to(source)
    elif change == "traversal":
        manifest["files_sha256"]["../outside"] = "a" * 64
        (root / "RELEASE-MANIFEST.json").write_text(json.dumps(manifest))
    elif change == "fifo":
        import os
        os.mkfifo(root / "unlisted-pipe")
    else:
        (root / "RELEASE-MANIFEST.json").write_text('{"schema": 1, "schema": 2}')
    with pytest.raises(ValueError):
        product.check_package(SimpleNamespace())
