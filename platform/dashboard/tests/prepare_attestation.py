"""Prepare an isolated browser-test server; private signing bytes never leave /tmp.

This is test setup only. The application never generates operator signing keys.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tomllib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=Path)
    parser.add_argument("scratch", type=Path)
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    if not scratch.is_relative_to(Path("/tmp")):
        raise ValueError("browser test setup must stay in /tmp")
    os.chmod(scratch, 0o700)
    cfg = tomllib.loads((args.workspace / "aegis.toml").read_text())
    key = Ed25519PrivateKey.generate()
    private = scratch / "test-signing-key.pem"
    public = scratch / "test-verification-key.pem"
    with private.open("xb") as stream:
        os.chmod(private, 0o600)
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with public.open("xb") as stream:
        stream.write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    lines = ["[storage]", f"root = {json.dumps(str(scratch / 'store'))}", "[attack_lab]", "enabled = false"]
    for name, backend in cfg["adapters"].items():
        lines.extend([f"[adapters.{name}]", f"command = {json.dumps(backend['command'])}", 'tasks = ["protect"]', "timeout_seconds = 300"])
    lines.extend([
        "[provenance]", "enabled = true", f"signing_key_path = {json.dumps(str(private))}",
        f"trusted_public_keys = [{json.dumps(str(public))}]", 'signer_name = "Dashboard browser test signer"',
        'build_repository = "https://github.com/Youssef-Boussabah/AEGIS"', 'build_commit = "691ce2717934c22dd30883b5dd8a586ebf78bf20"',
        "[sentinel]", "enabled = true", 'issuer = "Dashboard browser test issuer"',
        'enforcement_mode = "cooperating_enforced"', 'allowed_actions = ["analyze", "redistribute"]',
    ])
    with (scratch / "aegis.toml").open("x") as stream:
        os.chmod(scratch / "aegis.toml", 0o600)
        stream.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
