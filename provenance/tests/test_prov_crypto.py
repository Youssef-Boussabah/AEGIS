import pytest
from aegis_provenance.crypto import (
    compute_key_id,
    export_private_key_pem,
    export_public_key_pem,
    generate_keypair,
    load_private_key_pem,
    load_public_key,
    save_keypair_files,
    sign_bytes,
    verify_signature,
)


def test_keypair_generation_and_signing():
    kp = generate_keypair()
    assert len(kp.key_id) == 64
    data = b"important artifact bytes to sign"
    sig = sign_bytes(kp.private_key, data)
    assert isinstance(sig, str)
    assert verify_signature(kp.public_key, sig, data) is True
    assert verify_signature(kp.public_key, sig, b"tampered bytes") is False


def test_export_and_load_private_key():
    kp = generate_keypair()
    pem = export_private_key_pem(kp.private_key)
    assert "-----BEGIN PRIVATE KEY-----" in pem

    loaded = load_private_key_pem(pem)
    data = b"message"
    sig = sign_bytes(loaded, data)
    assert verify_signature(kp.public_key, sig, data) is True


def test_export_and_load_private_key_with_password():
    kp = generate_keypair()
    password = "secret-passphrase"
    pem = export_private_key_pem(kp.private_key, password=password)
    assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in pem

    loaded = load_private_key_pem(pem, password=password)
    data = b"message"
    sig = sign_bytes(loaded, data)
    assert verify_signature(kp.public_key, sig, data) is True

    # Bad password should fail
    with pytest.raises(Exception):
        load_private_key_pem(pem, password="wrong-password")


def test_export_and_load_public_key():
    kp = generate_keypair()
    pem = export_public_key_pem(kp.public_key)
    assert "-----BEGIN PUBLIC KEY-----" in pem

    loaded = load_public_key(pem)
    assert compute_key_id(loaded) == kp.key_id


def test_save_and_load_keypair_files(tmp_path):
    kp = generate_keypair()
    priv_file = tmp_path / "priv.pem"
    pub_file = tmp_path / "pub.pem"

    save_keypair_files(kp, priv_file, pub_file)
    assert priv_file.is_file()
    assert pub_file.is_file()

    loaded_priv = load_private_key_pem(priv_file.read_text(encoding="utf-8"))
    loaded_pub = load_public_key(pub_file.read_text(encoding="utf-8"))

    sig = sign_bytes(loaded_priv, b"payload")
    assert verify_signature(loaded_pub, sig, b"payload") is True
