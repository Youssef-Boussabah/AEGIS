"""Test helpers for signed-job tests. Not for production use.

Keys made here are ephemeral test keys written to a caller-provided temporary
directory. Production signing keys are created by the operator with
``aegis-provenance keygen`` outside any repository; AEGIS never generates one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from aegis_provenance.crypto import KeyPair, generate_keypair, save_keypair_files

TEST_COMMIT = "0123456789abcdef0123456789abcdef01234567"
TEST_REPOSITORY = "https://example.invalid/aegis-test"


@dataclass(frozen=True)
class TestKeys:
    __test__ = False  # not a pytest test class

    signer: KeyPair
    signer_private: Path
    signer_public: Path
    other: KeyPair
    other_private: Path
    other_public: Path


def make_test_keys(directory: Path) -> TestKeys:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    signer, other = generate_keypair(), generate_keypair()
    paths = {}
    for label, pair in (("signer", signer), ("other", other)):
        priv, pub = directory / f"{label}.pem", directory / f"{label}.pub.pem"
        save_keypair_files(pair, priv, pub)
        paths[label] = (priv, pub)
    return TestKeys(
        signer=signer,
        signer_private=paths["signer"][0],
        signer_public=paths["signer"][1],
        other=other,
        other_private=paths["other"][0],
        other_public=paths["other"][1],
    )


def attestation_toml(
    *,
    signing_key: Path | None = None,
    trusted: list[Path] | None = None,
    password_env: str | None = None,
    allowed_actions: list[str] | None = None,
    enforcement_mode: str = "cooperating_enforced",
    valid_days: int | None = None,
    allowed_caller_ids: list[str] | None = None,
) -> str:
    """TOML for [provenance] / [sentinel]; sections are enabled only when given."""
    lines: list[str] = []
    if signing_key is not None or trusted:
        lines += ["[provenance]", "enabled = true"]
        if signing_key is not None:
            lines += [
                f"signing_key_path = {json.dumps(str(signing_key))}",
                'signer_name = "AEGIS test signer"',
                f"build_repository = {json.dumps(TEST_REPOSITORY)}",
                f"build_commit = {json.dumps(TEST_COMMIT)}",
            ]
        if password_env is not None:
            lines.append(f"signing_key_password_env = {json.dumps(password_env)}")
        lines.append(f"trusted_public_keys = {json.dumps([str(p) for p in trusted or []])}")
    if allowed_actions is not None:
        lines += [
            "[sentinel]",
            "enabled = true",
            'issuer = "AEGIS test issuer"',
            f"enforcement_mode = {json.dumps(enforcement_mode)}",
            f"allowed_actions = {json.dumps(allowed_actions)}",
        ]
        if valid_days is not None:
            lines.append(f"valid_days = {valid_days}")
        if allowed_caller_ids is not None:
            lines.append(f"allowed_caller_ids = {json.dumps(allowed_caller_ids)}")
    return "\n".join(lines) + "\n"
