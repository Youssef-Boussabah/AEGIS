from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.config import config_from_mapping, default_config_text, load_config
from aegis_core.errors import AegisError
from aegis_core.models import ErrorCode
from aegis_core.storage import LocalArtifactStore, safe_artifact_name, validate_job_id


def test_default_config_registers_no_backends(tmp_path: Path):
    path = tmp_path / "aegis.toml"
    path.write_text(default_config_text())
    config = load_config(path)
    assert config.adapters == {}
    assert config.attack_lab.enabled is False
    assert config.storage.root == (tmp_path / ".aegis").resolve()


def test_missing_config_is_explicit(tmp_path: Path):
    with pytest.raises(AegisError) as info:
        load_config(tmp_path / "nope.toml")
    assert info.value.code is ErrorCode.CONFIG_NOT_FOUND


def test_invalid_toml_is_explicit(tmp_path: Path):
    path = tmp_path / "aegis.toml"
    path.write_text("[storage\n")
    with pytest.raises(AegisError) as info:
        load_config(path)
    assert info.value.code is ErrorCode.CONFIG_INVALID


@pytest.mark.parametrize(
    "data",
    [
        {"adapters": {"x": {"command": []}}},
        {"adapters": {"x": {"command": ["ok", ""]}}},
        {"adapters": {"Bad Name": {"command": ["ok"]}}},
        {"adapters": {"x": {"command": ["ok"], "env_passthrough": ["A=B"]}}},
        {"adapters": {"x": {"command": ["ok"], "tasks": ["exploit"]}}},
        {"unknown_section": {}},
    ],
)
def test_invalid_config_values_are_rejected(tmp_path: Path, data):
    with pytest.raises(AegisError) as info:
        config_from_mapping(data, base_dir=tmp_path)
    assert info.value.code is ErrorCode.CONFIG_INVALID


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("a b;rm -rf $(x).bin", "a_b_rm_-rf_x_.bin"),
        ("..", "artifact.bin"),
        (".hidden", "hidden"),
        ("C:\\win\\file.exe", "file.exe"),
    ],
)
def test_safe_artifact_name(raw, expected):
    assert safe_artifact_name(raw) == expected


@pytest.mark.parametrize("job_id", ["../x", "ABC", "", "0" * 31, "g" * 32])
def test_job_ids_are_validated(job_id):
    with pytest.raises(AegisError) as info:
        validate_job_id(job_id)
    assert info.value.code is ErrorCode.JOB_NOT_FOUND


def test_ingest_enforces_size_limit(tmp_path: Path):
    store = LocalArtifactStore(tmp_path / "store", max_input_bytes=4)
    store.create_job_dir("a" * 32)
    with pytest.raises(AegisError) as info:
        store.ingest_input("a" * 32, "x.bin", data=b"12345")
    assert info.value.code is ErrorCode.INPUT_TOO_LARGE
    source = tmp_path / "big.bin"
    source.write_bytes(b"123456789")
    with pytest.raises(AegisError):
        store.ingest_input("a" * 32, "big.bin", source=source)
    assert not (store.inputs_dir("a" * 32) / "big.bin").exists()


def test_ingest_hashes_input(tmp_path: Path):
    store = LocalArtifactStore(tmp_path / "store", max_input_bytes=1024)
    store.create_job_dir("b" * 32)
    artifact = store.ingest_input("b" * 32, "../evil name.bin", data=b"hello")
    assert artifact.sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert artifact.name == "evil_name.bin"
    assert store.artifact_path(artifact).read_bytes() == b"hello"
