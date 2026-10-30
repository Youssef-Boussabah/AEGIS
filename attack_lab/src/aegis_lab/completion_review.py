"""Offline, post-hoc review of a legacy Nebius metadata rejection; no execution.

The original record and its v1 parsed response remain immutable. A new report
binds their bytes and describes only an independent parser/envelope revalidation.
It is not an experiment replacement or an input to behavioral scoring.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from .canonical import canonical_json_bytes
from .disclosure import InferenceApproval
from .experiment import evaluate_response, verify_experiment
from .manifest import Hash, TrialManifest
from .private_evidence import PrivateEvidence
from .provider import (
    LEGACY_COMPLETION_PARSER, NEBIUS_REASONING_COMPLETION_PARSER, NEBIUS_REASONING_FIELDS,
    Usage, parse_completion,
)
from .reconstruction import parse_candidate_envelope, prepare_reconstruction
from .safe_io import parse_strict_json, publish_new_file, read_regular_file


class CompletionReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aegis.lab.completion-revalidation.v1"] = "aegis.lab.completion-revalidation.v1"
    analysis_kind: Literal["post_hoc_parser_compatibility_review"] = "post_hoc_parser_compatibility_review"
    historical_experiment_sha256: Hash
    response_sha256: Hash
    historical_completion_parser: Literal["aegis.lab.completion-parser.v1"] = LEGACY_COMPLETION_PARSER
    revalidation_completion_parser: Literal["aegis.lab.nebius-reasoning-text.v2"] = NEBIUS_REASONING_COMPLETION_PARSER
    historical_generation_status: Literal["invalid_output"] = "invalid_output"
    post_hoc_status: Literal["candidate_text_revalidated_but_behaviorally_unscored", "rejected"]
    requested_model: str = Field(max_length=200, pattern=r"^nvidia/[A-Za-z0-9][A-Za-z0-9_.-]*$")
    reasoning_fields_validated: tuple[Literal["reasoning", "reasoning_content"], ...]
    candidate_envelope_valid: StrictBool
    candidate_sha256: Hash | None
    reported_usage: Usage | None
    execution_performed: Literal[False] = False
    behavioral_scoring: Literal["unscored"] = "unscored"
    attack_effectiveness: Literal["not_established"] = "not_established"
    limitations: tuple[str, ...] = (
        "Post-hoc parser review; the historical experiment and its invalid_output status are unchanged.",
        "A valid candidate envelope is text only, not compilation, execution or reverse-engineering success.",
        "Usage and identity are provider reports; local unsigned hashes do not attest provider origin.",
        "No new inference request, approval consumption or spending occurred in this analysis.",
    )

    @field_validator("execution_performed", mode="before")
    @classmethod
    def exact_execution_boolean(cls, value):
        if type(value) is not bool:
            raise ValueError("strict_boolean_required")
        return value


def review_completion(directory: Path, *, expected_experiment_sha256: str | None = None) -> CompletionReview:
    """Reverify legacy history first, then independently inspect one completed reply."""
    data = read_regular_file(directory / "experiment.json", 2 * 1024 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    if expected_experiment_sha256 is not None and digest != expected_experiment_sha256:
        raise ValueError("historical_experiment_digest_mismatch")
    record = verify_experiment(directory, expected_sha256=digest)
    if (record.completion_parser != LEGACY_COMPLETION_PARSER or record.generation_status != "invalid_output"
            or not record.provider.external_disclosure or record.provider.provider != "Nebius"):
        raise ValueError("legacy_nebius_invalid_output_record_required")
    if (len(record.steps) != 1 or record.steps[0].submission != "completed"
            or not record.steps[0].response_sha256 or not record.steps[0].parsed_response_sha256):
        raise ValueError("single_completed_response_required")
    store = PrivateEvidence(directory / "private-evidence", create=False)
    request = parse_strict_json(store.get(record.prepared_request_sha256))
    manifest = TrialManifest.model_validate_json(store.get(record.manifest_sha256))
    prepared = prepare_reconstruction(manifest, store.get(record.report_sha256),
        max_output_tokens=request["max_tokens"], top_p=request.get("top_p"))
    approval = InferenceApproval.model_validate_json(store.get(record.inference_approval_sha256))
    raw = store.get(record.steps[0].response_sha256)
    response = parse_completion(raw, parser=NEBIUS_REASONING_COMPLETION_PARSER)
    source, error = parse_candidate_envelope(response.content or "", language=prepared.language,
                                             interface=prepared.expected_interface)
    outcome, accepted_source = evaluate_response(prepared, record.configuration, response,
        input_bound=approval.context_tokens, candidate_present=False, tool_calls=0)
    accepted = outcome == "generated_but_behaviorally_unscored" and accepted_source is not None
    # Only fixed allowlisted names enter the report, never arbitrary private keys.
    message = parse_strict_json(raw)["choices"][0]["message"]
    fields = tuple(sorted(key for key in NEBIUS_REASONING_FIELDS if isinstance(message.get(key), str)))
    return CompletionReview(historical_experiment_sha256=digest, response_sha256=response.body_sha256,
        post_hoc_status="candidate_text_revalidated_but_behaviorally_unscored" if accepted else "rejected",
        requested_model=record.requested_model, reasoning_fields_validated=fields,
        candidate_envelope_valid=error is None,
        candidate_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest() if accepted else None,
        reported_usage=response.usage)


def verify_review(directory: Path, report_path: Path, *, expected_experiment_sha256: str | None = None):
    """Recompute every field; a matching source hash alone cannot validate a sidecar."""
    data = read_regular_file(report_path, 64 * 1024)
    supplied = CompletionReview.model_validate(parse_strict_json(data))
    expected = review_completion(directory, expected_experiment_sha256=expected_experiment_sha256)
    if supplied != expected:
        raise ValueError("post_hoc_report_revalidation_mismatch")
    return expected, hashlib.sha256(data).hexdigest()


def write_review(directory: Path, output: Path) -> CompletionReview:
    if output.resolve().is_relative_to(directory.resolve()):
        raise ValueError("original_archive_is_read_only")
    result = review_completion(directory)
    publish_new_file(output, canonical_json_bytes(result.model_dump(mode="json")), 64 * 1024)
    return result


def main(argv=None):
    from .diagnostics import SafeArgumentParser

    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New report outside the historical archive")
    args = parser.parse_args(argv)
    try:
        result = write_review(args.directory, args.output)
        print(json.dumps(result.model_dump(mode="json"), sort_keys=True))
        return 0 if result.post_hoc_status == "candidate_text_revalidated_but_behaviorally_unscored" else 1
    except Exception:
        print("post_hoc_review_failed: invalid_or_unverifiable_input_or_publication", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
