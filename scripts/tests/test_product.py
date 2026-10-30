"""Product tooling checks: no candidate execution or fabricated protection evidence."""
import importlib.util
import json
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
        assert manifest["license_status"] == "pending_owner_review"
        for name, expected in manifest["files_sha256"].items():
            import hashlib
            assert hashlib.sha256(tar.extractfile("aegis/" + name).read()).hexdigest() == expected
        assert "PRIVATE_MARKER" not in str(manifest)
    with pytest.raises(FileExistsError):
        product.package(args)
    product.package(SimpleNamespace(workspace=tmp_path / "package-2"))
    assert archive.read_bytes() == (tmp_path / "package-2/aegis-local-review.tar.gz").read_bytes()
