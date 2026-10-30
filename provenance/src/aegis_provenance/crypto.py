"""Cryptographic routines for Ed25519 signing and verification.

Never commits private keys to repository or logs.
Uses standard cryptography primitives.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyPair(NamedTuple):
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    key_id: str


def compute_key_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """Compute deterministic SHA-256 key_id hex from raw public key bytes."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw_bytes).hexdigest()


def generate_keypair() -> KeyPair:
    """Generate a new secure Ed25519 keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return KeyPair(private_key=priv, public_key=pub, key_id=compute_key_id(pub))


def export_private_key_pem(
    priv: ed25519.Ed25519PrivateKey, password: str | None = None
) -> str:
    """Export private key as standard PKCS#8 PEM string."""
    enc = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    pem_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    return pem_bytes.decode("utf-8")


def load_private_key_pem(
    pem_str: str, password: str | None = None
) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PKCS#8 PEM string."""
    key = serialization.load_pem_private_key(
        pem_str.encode("utf-8"),
        password=password.encode("utf-8") if password else None,
    )
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Key in PEM is not an Ed25519 private key")
    return key


def export_public_key_pem(pub: ed25519.Ed25519PublicKey) -> str:
    """Export public key as SubjectPublicKeyInfo PEM string."""
    pem_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")


def load_public_key(key_str: str) -> ed25519.Ed25519PublicKey:
    """Load public key from SubjectPublicKeyInfo PEM or Raw base64 string."""
    stripped = key_str.strip()
    if "-----BEGIN PUBLIC KEY-----" in stripped:
        loaded = serialization.load_pem_public_key(stripped.encode("utf-8"))
        if not isinstance(loaded, ed25519.Ed25519PublicKey):
            raise ValueError("PEM key is not an Ed25519 public key")
        return loaded

    # Try raw 32-byte base64
    try:
        raw_bytes = base64.b64decode(stripped, validate=True)
        if len(raw_bytes) == 32:
            return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    except Exception:
        pass

    raise ValueError("Unrecognized public key format: expected PEM or 32-byte Base64")


def sign_bytes(priv: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    """Sign canonical data bytes and return base64 signature string."""
    sig = priv.sign(data)
    return base64.b64encode(sig).decode("ascii")


def verify_signature(
    pub: ed25519.Ed25519PublicKey, signature_b64: str, data: bytes
) -> bool:
    """Verify base64 signature over data bytes."""
    try:
        sig_bytes = base64.b64decode(signature_b64, validate=True)
        pub.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def save_keypair_files(
    keypair: KeyPair,
    private_key_path: Path,
    public_key_path: Path,
    password: str | None = None,
) -> None:
    """Save keypair to files; the private key is created 0600 from the start.

    The private key file is never world- or group-readable, not even briefly:
    it is opened with mode 0600 (an existing file is replaced via a private
    temporary file) instead of being written first and chmod-ed afterwards.
    """
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    priv_pem = export_private_key_pem(keypair.private_key, password=password)
    pub_pem = export_public_key_pem(keypair.public_key)

    _write_private(private_key_path, priv_pem.encode("utf-8"))
    public_key_path.write_text(pub_pem, encoding="utf-8")


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

