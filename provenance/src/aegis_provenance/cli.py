"""CLI for AEGIS Provenance manifest generation, signing, and verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis_provenance.crypto import (
    generate_keypair,
    load_private_key_pem,
    load_public_key,
    save_keypair_files,
)
from aegis_provenance.manifest import sign_artifact, verify_artifact_manifest
from aegis_provenance.models import (
    BuildReference,
    ConfigurationIdentity,
    ManifestEnvelope,
    SignerIdentity,
    ToolchainInfo,
)


def _cmd_keygen(args: argparse.Namespace) -> int:
    priv_path = Path(args.private_key).resolve()
    pub_path = Path(args.public_key).resolve()

    if priv_path.exists() and not args.force:
        sys.stderr.write(f"Error: private key file already exists: {priv_path}\n")
        return 1
    from aegis_provenance.jobs import inside_git_work_tree

    repo = inside_git_work_tree(priv_path)
    if repo is not None:
        sys.stderr.write(
            f"Error: refusing to write a private key inside the Git work tree {repo}; "
            "choose a path outside any repository.\n"
        )
        return 2

    kp = generate_keypair()
    save_keypair_files(kp, priv_path, pub_path, password=args.password)
    sys.stdout.write(f"Generated Ed25519 keypair.\nKey ID: {kp.key_id}\n")
    sys.stdout.write(f"Private key saved to: {priv_path}\nPublic key saved to: {pub_path}\n")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    artifact_path = Path(args.artifact).resolve()
    if not artifact_path.is_file():
        sys.stderr.write(f"Error: artifact not found: {artifact_path}\n")
        return 1

    priv_pem = Path(args.private_key).read_text(encoding="utf-8")
    priv_key = load_private_key_pem(priv_pem, password=args.password)

    signer = SignerIdentity(
        name=args.signer_name,
        organization=args.signer_org or None,
        contact=args.signer_contact or None,
    )
    build_ref = BuildReference(
        repository=args.repo,
        commit=args.commit,
        branch=args.branch or None,
        build_job_id=args.job_id or None,
    )
    toolchain = ToolchainInfo(
        compiler=args.compiler,
        compiler_version=args.compiler_version,
        platform=args.platform,
        target_triple=args.target_triple or None,
    )
    configuration = ConfigurationIdentity(
        profile=args.profile,
        backend=args.backend or None,
        options_digest=args.options_digest or None,
    )

    envelope = sign_artifact(
        artifact_path=artifact_path,
        private_key=priv_key,
        signer=signer,
        build_reference=build_ref,
        toolchain=toolchain,
        configuration=configuration,
    )

    envelope_json = envelope.model_dump_json(indent=2)
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(envelope_json, encoding="utf-8")
        sys.stdout.write(f"Manifest envelope written to: {out_path}\n")
    else:
        sys.stdout.write(envelope_json + "\n")

    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    artifact_path = Path(args.artifact).resolve()
    manifest_path = Path(args.manifest).resolve()

    if not manifest_path.is_file():
        sys.stderr.write(f"Error: manifest file not found: {manifest_path}\n")
        return 2

    envelope_data = manifest_path.read_text(encoding="utf-8")

    trusted_keys = []
    for k_path_str in args.trusted_key:
        k_path = Path(k_path_str).resolve()
        if not k_path.is_file():
            sys.stderr.write(f"Error: trusted key file not found: {k_path}\n")
            return 2
        trusted_keys.append(k_path.read_text(encoding="utf-8"))

    result = verify_artifact_manifest(
        artifact_path=artifact_path,
        envelope_input=envelope_data,
        trusted_keys=trusted_keys,
    )

    if result.valid:
        sys.stdout.write("VERIFICATION SUCCESSFUL\n")
        sys.stdout.write(f"Artifact SHA-256 : {result.artifact_sha256}\n")
        sys.stdout.write(f"Signing Key ID   : {result.key_id}\n")
        sys.stdout.write(f"Signer           : {result.signer_name}\n")
        sys.stdout.write(f"Verified At      : {result.verified_at.isoformat()}\n")
        return 0
    else:
        sys.stderr.write(f"VERIFICATION FAILED: [{result.error_code}] {result.message}\n")
        return 1


def _cmd_inspect(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.is_file():
        sys.stderr.write(f"Error: manifest file not found: {manifest_path}\n")
        return 1

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        envelope = ManifestEnvelope.model_validate(data)
    except Exception as exc:
        sys.stderr.write(f"Error: invalid manifest envelope: {exc}\n")
        return 1

    sys.stdout.write("Manifest Envelope Summary (NOTICE: Unverified inspection)\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write(f"Envelope Version : {envelope.envelope_version}\n")
    sys.stdout.write(f"Algorithm        : {envelope.algorithm}\n")
    sys.stdout.write(f"Key ID           : {envelope.key_id}\n")
    sys.stdout.write(f"Artifact Name    : {envelope.payload.artifact_name}\n")
    sys.stdout.write(f"Artifact SHA-256 : {envelope.payload.artifact_sha256}\n")
    sys.stdout.write(f"Artifact Bytes   : {envelope.payload.artifact_size_bytes}\n")
    sys.stdout.write(f"Signer           : {envelope.payload.signer.name}\n")
    sys.stdout.write(f"Repository       : {envelope.payload.build_reference.repository}\n")
    sys.stdout.write(f"Commit           : {envelope.payload.build_reference.commit}\n")
    sys.stdout.write(f"Toolchain        : {envelope.payload.toolchain.compiler} {envelope.payload.toolchain.compiler_version}\n")
    sys.stdout.write(f"Platform         : {envelope.payload.toolchain.platform}\n")
    sys.stdout.write(f"Profile          : {envelope.payload.configuration.profile}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-provenance",
        description="AEGIS Provenance: offline signed manifests and public key verification.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_kg = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    p_kg.add_argument("--private-key", required=True, help="Path to write private key PEM")
    p_kg.add_argument("--public-key", required=True, help="Path to write public key PEM")
    p_kg.add_argument("--password", default=None, help="Optional private key encryption password")
    p_kg.add_argument("--force", action="store_true", help="Overwrite existing key files")
    p_kg.set_defaults(func=_cmd_keygen)

    # sign
    p_sign = sub.add_parser("sign", help="Sign an artifact and produce a manifest envelope")
    p_sign.add_argument("artifact", help="Path to final artifact file")
    p_sign.add_argument("--private-key", required=True, help="Path to signer private key PEM")
    p_sign.add_argument("--password", default=None, help="Password for private key if encrypted")
    p_sign.add_argument("--signer-name", required=True, help="Signer name or identifier")
    p_sign.add_argument("--signer-org", default=None, help="Signer organization")
    p_sign.add_argument("--signer-contact", default=None, help="Signer contact")
    p_sign.add_argument("--repo", required=True, help="Source repository URL or path")
    p_sign.add_argument("--commit", required=True, help="Git commit hash")
    p_sign.add_argument("--branch", default=None, help="Git branch")
    p_sign.add_argument("--job-id", default=None, help="AEGIS job ID")
    p_sign.add_argument("--compiler", default="clang", help="Compiler name")
    p_sign.add_argument("--compiler-version", default="22.1.8", help="Compiler version")
    p_sign.add_argument("--platform", default=sys.platform, help="Target platform")
    p_sign.add_argument("--target-triple", default=None, help="Target architecture triple")
    p_sign.add_argument("--profile", default="default", help="Build/protection profile")
    p_sign.add_argument("--backend", default=None, help="Protection backend used")
    p_sign.add_argument("--options-digest", default=None, help="Digest of protection options")
    p_sign.add_argument("-o", "--output", default=None, help="Path to output manifest JSON envelope")
    p_sign.set_defaults(func=_cmd_sign)

    # verify
    p_ver = sub.add_parser("verify", help="Verify an artifact against a signed manifest")
    p_ver.add_argument("artifact", help="Path to artifact file to verify")
    p_ver.add_argument("--manifest", required=True, help="Path to manifest envelope JSON")
    p_ver.add_argument(
        "--trusted-key",
        required=True,
        action="append",
        help="Path to trusted public key PEM (can be specified multiple times)",
    )
    p_ver.set_defaults(func=_cmd_verify)

    # inspect
    p_insp = sub.add_parser("inspect", help="Inspect manifest envelope contents (unverified)")
    p_insp.add_argument("manifest", help="Path to manifest envelope JSON")
    p_insp.set_defaults(func=_cmd_inspect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

