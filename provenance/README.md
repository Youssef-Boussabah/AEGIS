# AEGIS Provenance & Verification

**Module:** `provenance/`  
**Role:** D — Signature, Sentinel & Verification  
**Branch:** `feat/signature-sentinel`  
**Tracking:** Issue [#12](https://github.com/Youssef-Boussabah/AEGIS/issues/12)  
**Status:** Implemented and tested.

---

## 1. Overview

`aegis-provenance` implements offline, cryptographic artifact provenance signing and verification using Ed25519 signatures (RFC 8032) and deterministic canonical JSON envelopes (RFC 8785).

Signing occurs **after** artifact bytes are final, binding:
- Artifact SHA-256 digest and size
- Source and build reference (repository URL, commit hash, branch, job ID)
- Toolchain specification (compiler, version, platform, target triple)
- Configuration identity (protection profile, backend, options digest)
- Signer identity and signing key identifier (SHA-256 fingerprint of the public key)

---

## 2. Cryptographic Architecture

1. **Standard Cryptography:** Uses `cryptography.hazmat.primitives.asymmetric.ed25519`. No custom cryptography.
2. **Canonical Serialization:** The covered manifest payload is converted to canonical UTF-8 bytes using RFC 8785 JSON Canonicalization Scheme principles (lexicographically sorted keys, compact separators, normalized ISO-8601 UTC datetimes).
3. **Key Isolation:** Private keys are stored in standard PKCS#8 PEM format (with optional encryption) strictly outside the repository and outside logs.
4. **Verification Acceptance Rules:**
   - **Valid:** Artifact on disk matches SHA-256 digest, public key matches Key ID, public key is present in trusted keys, and signature validates over canonical payload.
   - **Tampered Artifact:** If the artifact on disk has been modified, verification fails with `ARTIFACT_TAMPERED`.
   - **Tampered Manifest:** If any covered field (commit, toolchain, digest) is modified, signature verification fails with `SIGNATURE_INVALID`.
   - **Untrusted Key:** If an untrusted key signed the envelope, verification fails with `UNTRUSTED_KEY`.
   - **Malformed Envelope / Data:** Fails with `MANIFEST_MALFORMED`.
   - **Unsupported Version:** Rejects version mismatch with `UNSUPPORTED_VERSION`.

---

## 3. CLI Usage

The package exposes the `aegis-provenance` CLI tool (also runnable via `python -m aegis_provenance.cli`).

### Generate Keypair
```bash
aegis-provenance keygen --private-key /path/to/private.pem --public-key /path/to/public.pem
```

### Sign an Artifact
```bash
aegis-provenance sign build/output/protected.ll \
  --private-key /path/to/private.pem \
  --signer-name "AEGIS Release Bot" \
  --signer-org "Security Engineering" \
  --repo "https://github.com/Youssef-Boussabah/AEGIS" \
  --commit "a5efcd6a7b7b1e7695995377c6b1332a14618721" \
  --compiler "clang" \
  --compiler-version "22.1.8" \
  --profile "release-shield" \
  -o build/output/provenance.manifest.json
```

### Inspect Manifest (Unverified Notice)
```bash
aegis-provenance inspect build/output/provenance.manifest.json
```

### Verify an Artifact
```bash
aegis-provenance verify build/output/protected.ll \
  --manifest build/output/provenance.manifest.json \
  --trusted-key /path/to/trusted_public.pem
```

Exit codes:
- `0`: Verification succeeded
- `1`: Verification failed (tampered artifact, invalid signature, or untrusted key)
- `2`: Missing file or input error

---

## 4. Watermark Research

See [RESEARCH_WATERMARK.md](RESEARCH_WATERMARK.md) for detailed empirical evaluation of binary framing and LLVM IR watermarking, false-positive controls (0.0% FPR), collision metrics, and transformation retention.
