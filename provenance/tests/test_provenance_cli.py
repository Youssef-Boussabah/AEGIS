import json
from pathlib import Path

from aegis_provenance.cli import main


def test_cli_full_flow(tmp_path: Path, monkeypatch, capsys):
    priv_file = tmp_path / "private.pem"
    pub_file = tmp_path / "public.pem"
    artifact_file = tmp_path / "test_artifact.bin"
    manifest_file = tmp_path / "manifest.json"

    artifact_file.write_bytes(b"artifact bytes to sign and verify")

    # 1. keygen
    rc = main(["keygen", "--private-key", str(priv_file), "--public-key", str(pub_file)])
    assert rc == 0
    assert priv_file.is_file()
    assert pub_file.is_file()

    # 2. sign
    rc = main([
        "sign",
        str(artifact_file),
        "--private-key", str(priv_file),
        "--signer-name", "Test Signer",
        "--repo", "https://github.com/Youssef-Boussabah/AEGIS",
        "--commit", "abcdef1234567890abcdef1234567890abcdef12",
        "--compiler", "clang",
        "--compiler-version", "22.1.8",
        "-o", str(manifest_file),
    ])
    assert rc == 0
    assert manifest_file.is_file()

    # 3. inspect
    capsys.readouterr()
    rc = main(["inspect", str(manifest_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Manifest Envelope Summary" in out
    assert "Test Signer" in out

    # 4. verify success
    capsys.readouterr()
    rc = main([
        "verify",
        str(artifact_file),
        "--manifest", str(manifest_file),
        "--trusted-key", str(pub_file),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "VERIFICATION SUCCESSFUL" in out

    # 5. verify failure on tampered artifact
    artifact_file.write_bytes(b"tampered!")
    capsys.readouterr()
    rc = main([
        "verify",
        str(artifact_file),
        "--manifest", str(manifest_file),
        "--trusted-key", str(pub_file),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "VERIFICATION FAILED: [ARTIFACT_TAMPERED]" in err
