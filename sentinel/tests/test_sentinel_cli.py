from pathlib import Path

from aegis_sentinel.cli import main


def test_sentinel_cli_flow(tmp_path: Path, capsys):
    artifact = tmp_path / "app.so"
    artifact.write_bytes(b"sample shared library binary data")
    policy_file = tmp_path / "sentinel_policy.json"

    # 1. create policy
    rc = main([
        "create",
        str(artifact),
        "--issuer", "AEGIS Sentinel Authority",
        "--mode", "cooperating_enforced",
        "-o", str(policy_file),
    ])
    assert rc == 0
    assert policy_file.is_file()

    # 2. validate policy
    capsys.readouterr()
    rc = main(["validate", str(policy_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "VALID Sentinel Policy" in out

    # 3. inspect policy
    capsys.readouterr()
    rc = main(["inspect", str(policy_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Sentinel Rights & Policy Document" in out
    assert "AEGIS Sentinel Authority" in out

    # 4. evaluate permitted action (execute is allowed by default)
    capsys.readouterr()
    rc = main([
        "evaluate",
        str(policy_file),
        "--action", "execute",
        "--artifact", str(artifact),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ACTION PERMITTED: [execute]" in out

    # 5. evaluate denied action (analyze is denied by default)
    capsys.readouterr()
    rc = main([
        "evaluate",
        str(policy_file),
        "--action", "analyze",
        "--artifact", str(artifact),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "ACTION DENIED: [analyze]" in err
