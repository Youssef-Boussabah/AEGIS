#!/usr/bin/env python3
"""Read-only imports of offline observations and explicitly trusted replay receipts."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from benchmark import (Invalid, MAX_JSON, ROOT, canonical, checked, contained, digest, exact, identity,
                       integer, load, names, parse_json, read_file, reference, require, sha,
                       stamp, text, timestamp, utcnow, validate_controls, validate_manifest,
                       write_json)

SCHEMA = "aegis.reconstruction.evidence.v1"
KINDS = ("ghidra", "rea", "nemotron_summary", "lab_experiment", "behavioral_receipt")


def lab_modules():
    """Optional parsers only; importing these does not launch tools/providers."""
    sys.path.insert(0, str(ROOT / "attack_lab/src"))
    try:
        from aegis_lab.evidence import parse_ghidra_report, ghidra_configuration_sha256
        from aegis_lab.public_summary import ReconstructionEvidence, ComparisonEvidence
    except ImportError:
        raise Invalid("optional_lab_parser_unavailable_use_repository_venv") from None
    return parse_ghidra_report, ghidra_configuration_sha256, ReconstructionEvidence, ComparisonEvidence


def check_context(root, prompt, m, artifact, oracle=None):
    if type(prompt) is dict and prompt.get("format") == "aegis_lab":
        return check_lab_context(root, prompt, m, artifact, oracle)
    exact(prompt, "template system context rendered")
    data = {name: checked(root, ref, MAX_JSON) for name, ref in prompt.items()}
    controls = m["attacker_controls"]
    require(digest(data["template"]) == controls["prompt_template_sha256"] and
            digest(data["system"]) == controls["system_prompt_sha256"], "noncomparable_prompts")
    require(data["template"].count(b"{{CONTEXT}}") == 1, "invalid_prompt_template")
    require(data["rendered"] == data["template"].replace(b"{{CONTEXT}}", data["context"]),
            "rendered_prompt_mismatch")
    context = parse_json(data["context"])
    exact(context, "artifact_sha256 functions")
    require(context["artifact_sha256"] == artifact["file"]["sha256"], "prompt_artifact_mismatch")
    require(type(context["functions"]) is list, "invalid_context")
    for function in context["functions"]:
        exact(function, "name decompiled_c")
        require(type(function["decompiled_c"]) is str and 0 < len(function["decompiled_c"]) <= 100000,
                "invalid_context")
    require([f["name"] for f in context["functions"]] == m["targets"], "prompt_target_mismatch")
    # Canonical bytes exclude hidden extra fields or ambiguities in normalization.
    require(data["context"] == canonical(context), "noncanonical_context")
    return context


def check_lab_context(root, prompt, m, artifact, oracle=None):
    """Rebuild the real production request; never substitute a lookalike prompt."""
    exact(prompt, "format manifest report request configuration")
    lab_modules()
    from aegis_lab.manifest import TrialManifest
    from aegis_lab.reconstruction import prepare_reconstruction
    from aegis_lab.experiment import WorkflowConfig, initial_messages, live_workflow_sha256
    from aegis_lab.provider import InferenceRequest
    lm = TrialManifest.model_validate_json(checked(root, prompt["manifest"], MAX_JSON))
    require([lm.target.function] == m["targets"], "lab_target_mismatch")
    require(lm.target.final_artifact_sha256 == artifact["file"]["sha256"], "lab_artifact_mismatch")
    controls = m["attacker_controls"]
    config = WorkflowConfig.model_validate(prompt["configuration"])
    reviewed_request = parse_json(checked(root, prompt["request"], MAX_JSON))
    prepared = prepare_reconstruction(lm, checked(root, prompt["report"], MAX_JSON),
                                      max_output_tokens=controls["max_output_tokens"],
                                      enable_thinking=reviewed_request.get("chat_template_kwargs", {}).get("enable_thinking"))
    if oracle is not None:
        from aegis_lab.c_abi import parse_interface
        require(parse_interface(prepared.expected_interface).arity == len(oracle["cases"][0]["arguments"]),
                "lab_oracle_interface_mismatch")
    request = InferenceRequest(**{**prepared.request.model_dump(), "messages": initial_messages(prepared), "store": False}).to_body()
    require(reviewed_request == request, "lab_request_mismatch")
    expected = {"prompt_template_sha256": lm.attack.prompt_sha256,
        "system_prompt_sha256": digest(request["messages"][0]["content"].encode()),
        "workflow_sha256": live_workflow_sha256(config),
        "request_parameters_sha256": identity({k: v for k, v in request.items() if k != "messages"}),
        "model_identity": lm.attack.model_id, "max_attempts": min(lm.budget.max_attempts, config.max_steps),
        "max_total_tokens": lm.budget.max_model_tokens, "time_budget_seconds": lm.budget.max_wall_seconds,
        "random_seed": lm.attack.sampling_seed}
    require(all(controls[k] == v for k, v in expected.items()), "lab_request_controls_mismatch")
    require(not any((lm.access.access_to_original_source, lm.access.access_to_symbols,
        lm.access.repository_retrieval_enabled, lm.access.network_enabled, lm.access.runtime_oracle_enabled)),
        "unsupported_lab_access")
    parse, _, _, _ = lab_modules()
    report = parse(checked(root, prompt["report"], MAX_JSON))
    # Apply this benchmark's tool and selected-target checks in addition to Lab's binder.
    ghidra_observation(checked(root, prompt["report"], MAX_JSON), m, artifact, None)
    functions = [{"name": n, "decompiled_c": next(f.decompiled_c for f in report.analysis.functions if f.name == n)}
                 for n in m["targets"]]
    return {"artifact_sha256": artifact["file"]["sha256"], "functions": functions,
            "_lab_manifest": lm, "_lab_prepared": prepared, "_lab_config": config}


def ghidra_observation(raw, m, artifact, context):
    parse, configuration_digest, _, _ = lab_modules()
    try:
        report = parse(raw)
    except Exception:
        raise Invalid("invalid_ghidra_report") from None
    require(report.binary.sha256 == artifact["file"]["sha256"] and
            report.binary.size_bytes == artifact["file"]["size_bytes"], "analysis_artifact_mismatch")
    tool = m["attacker_controls"]["analysis_tools"].get("Ghidra")
    require(tool is not None, "analysis_tool_not_permitted")
    require(configuration_digest(report.export) == tool["configuration_sha256"],
            "analysis_configuration_mismatch")
    require(tool["version"] == report.export.ghidra_version and
            tool["executable_sha256"] == report.export.ghidra_launcher_sha256, "analysis_tool_mismatch")
    selected = []
    for target in m["targets"]:
        matches = [f for f in report.analysis.functions if f.name == target]
        require(len(matches) == 1, "analysis_target_missing_or_ambiguous")
        selected.append(matches[0])
    if context is not None:
        require(context["functions"] == [{"name": f.name, "decompiled_c": f.decompiled_c} for f in selected],
                "context_analysis_mismatch")
    return {"classification": "structural_observation", "origin": "unsigned_ghidra_report",
            "functions": [{"name": f.name, "status": f.decompile_status,
                           "truncated": f.decompiled_c_truncated} for f in selected],
            "tool_version": report.export.ghidra_version,
            "tool_executable_sha256": report.export.ghidra_launcher_sha256,
            "behavioral_scoring": "unavailable"}


def rea_observation(raw, root, m, artifact, context):
    """A documented projection for REA; no assumption about Claude's native file schema."""
    r = parse_json(raw)
    exact(r, "schema artifact_sha256 targets tool raw observations")
    require(r["schema"] == "aegis.reconstruction.rea-observation.v1", "unsupported_rea_projection")
    require(r["artifact_sha256"] == artifact["file"]["sha256"] and r["targets"] == m["targets"],
            "analysis_target_or_artifact_mismatch")
    exact(r["tool"], "name version executable_sha256 configuration_sha256")
    require(r["tool"]["name"] == "REA", "wrong_analysis_tool")
    text(r["tool"]["version"])
    sha(r["tool"]["executable_sha256"])
    tool = m["attacker_controls"]["analysis_tools"].get("REA")
    require(tool is not None, "analysis_tool_not_permitted")
    require(r["tool"]["configuration_sha256"] == tool["configuration_sha256"],
            "analysis_configuration_mismatch")
    require(tool["version"] == r["tool"]["version"] and tool["executable_sha256"] == r["tool"]["executable_sha256"],
            "analysis_tool_mismatch")
    checked(root, r["raw"], MAX_JSON)
    require(type(r["observations"]) is list and [o.get("function") for o in r["observations"]] == m["targets"],
            "analysis_target_missing_or_ambiguous")
    for o in r["observations"]:
        exact(o, "function status decompiled_c structural_metrics")
        require(o["status"] in ("completed", "failed", "inconclusive"), "invalid_analysis_status")
        require(type(o["decompiled_c"]) is str and len(o["decompiled_c"]) <= 100000, "invalid_analysis_text")
        require((o["status"] == "completed") == bool(o["decompiled_c"]), "contradictory_analysis_status")
        require(type(o["structural_metrics"]) is dict and set(o["structural_metrics"]) <=
                {"decompiler_complexity", "basic_blocks", "instructions", "pcode_ops"}, "unsupported_structural_metric")
        for number in o["structural_metrics"].values():
            integer(number, 0, 10**12)
    if context is not None:
        require(context["functions"] == [{"name": o["function"], "decompiled_c": o["decompiled_c"]}
                                         for o in r["observations"]], "context_analysis_mismatch")
    return {"classification": "structural_observation", "origin": "operator_projection_unsigned",
            "functions": [{"name": o["function"], "status": o["status"], "structural_metrics": o["structural_metrics"]}
                          for o in r["observations"]],
            "raw_sha256": r["raw"]["sha256"], "behavioral_scoring": "unavailable"}


def nemotron_observation(raw, m, artifact, context):
    _, _, Reconstruction, Comparison = lab_modules()
    doc = parse_json(raw)
    try:
        if doc.get("kind") == "reconstruction":
            record = Reconstruction.model_validate(doc)
            summary = record.summary
        else:
            record = Comparison.model_validate(doc)
            # Existing research 'mirage' means combined Shield+Mirage, verified by artifact hash below.
            label = {"baseline": "baseline", "shield": "shield", "shield_mirage": "mirage"}[artifact["variant"]]
            row = next(r for r in record.summary.experiments if r.variant == label)
            require(row.summary is not None, "absent_research_trial")
            summary = row.summary
    except Invalid:
        raise
    except Exception:
        raise Invalid("invalid_nemotron_summary") from None
    require(summary.artifact_sha256 == artifact["file"]["sha256"], "research_artifact_mismatch")
    require(summary.requested_model == m["attacker_controls"]["model_identity"], "research_model_mismatch")
    if "_lab_manifest" in context:
        lm = context["_lab_manifest"]
        require(summary.trial_id == lm.trial_id and summary.pair_id == lm.pair_id, "research_trial_mismatch")
    return {"classification": "candidate_text_unscored" if summary.candidate_sha256 else "generation_observation",
        "origin": summary.evidence_label, "generation_status": summary.generation_status.value,
        "candidate_sha256": summary.candidate_sha256, "behavioral_scoring": "unavailable",
        "comparability": "operator_declared_sidecar_not_present_in_public_summary",
        "post_hoc_status": None if summary.post_hoc_review is None else summary.post_hoc_review.post_hoc_status,
        "provider_authenticity": "not_independently_attested"}


def lab_experiment(raw, directory, m, artifact, context, recorded_at):
    require("_lab_manifest" in context, "production_lab_prompt_required")
    from aegis_lab.experiment import verify_experiment
    from aegis_lab.public_summary import export_experiment
    from aegis_lab.private_evidence import PrivateEvidence
    from aegis_lab.disclosure import InferenceApproval
    try:
        record = verify_experiment(directory, expected_sha256=digest(raw))
        require(record.provider.external_disclosure, "live_provider_record_required")
        require(record.started_at is not None and record.finished_at is not None and
                timestamp(m["created_at"]) <= record.started_at <= record.finished_at <= timestamp(recorded_at),
                "stale_live_experiment")
        require(record.manifest_sha256 == context["_lab_manifest"].sha256() and
                record.report_sha256 == context["_lab_prepared"].evidence_sha256 and
                record.configuration == context["_lab_config"], "lab_archive_binding_mismatch")
        store = PrivateEvidence(directory / "private-evidence", create=False)
        approval = InferenceApproval.model_validate_json(store.get(record.inference_approval_sha256))
        controls = m["attacker_controls"]
        require(approval.context_tokens == controls["max_input_tokens"] and
                approval.max_total_tokens == controls["max_total_tokens"] and
                approval.max_spend_microusd == controls["max_spend_microusd"], "lab_approval_controls_mismatch")
        public = export_experiment(directory)
        result = nemotron_observation(canonical(public.model_dump(mode="json", by_alias=True)), m, artifact, context)
    except Invalid:
        raise
    except Exception:
        raise Invalid("invalid_lab_experiment_archive") from None
    result.update(comparability="production_request_and_private_archive_bindings_checked",
        freshness="production_record_window_checked_unsigned", source_observed_at=stamp(record.finished_at),
        reported_prompt_tokens=public.summary.prompt_tokens, reported_completion_tokens=public.summary.completion_tokens,
        reported_total_tokens=public.summary.reported_tokens,
        estimated_reported_cost_microusd=public.summary.estimated_reported_cost_microusd,
        reserved_spend_microusd=public.summary.reserved_spend_microusd,
        actual_invoice_cost_microusd=None)
    return result


def behavioral_receipt(raw, root, evidence, m, artifact, oracle, trusted_receipts):
    # A 'verified: true' flag inside an arbitrary file cannot establish independence.
    # The caller must pin a receipt digest obtained separately from a trusted reviewer.
    require(digest(raw) in trusted_receipts, "untrusted_independent_verification_receipt")
    r = parse_json(raw)
    exact(r, "schema verifier_id comparison_sha256 artifact_id artifact_sha256 controls_sha256 targets "
          "oracle_sha256 candidate_sha256 recorded_at isolation compilation cases")
    require(r["schema"] == "aegis.reconstruction.replay-receipt.v1", "unsupported_replay_receipt")
    text(r["verifier_id"], 128)
    for key, expected in (("comparison_sha256", identity(m)), ("artifact_id", artifact["id"]),
                          ("artifact_sha256", artifact["file"]["sha256"]),
                          ("controls_sha256", identity(m["attacker_controls"])), ("targets", m["targets"]),
                          ("oracle_sha256", m["oracle"]["sha256"]),
                          ("candidate_sha256", evidence["candidate"]["sha256"]),
                          ("recorded_at", evidence["recorded_at"])):
        require(r[key] == expected, "replay_binding_mismatch")
    checked(root, evidence["candidate"], MAX_JSON)  # Hash bytes only. Never import/compile/execute.
    exact(r["isolation"], "runtime validation_sha256 attestation_sha256")
    text(r["isolation"]["runtime"], 64)
    require(r["isolation"]["runtime"] not in ("host", "none", "test_double", "aegis-test-double"),
            "unvalidated_isolation")
    sha(r["isolation"]["validation_sha256"])
    sha(r["isolation"]["attestation_sha256"])
    exact(r["compilation"], "status compiler_sha256 log_sha256")
    require(r["compilation"]["status"] in ("succeeded", "candidate_rejected", "infrastructure_failure"),
            "invalid_compilation_status")
    require(r["compilation"]["compiler_sha256"] == m["build_conditions"]["tools"]["clang"]["sha256"],
            "replay_compiler_mismatch")
    sha(r["compilation"]["log_sha256"])
    require(type(r["cases"]) is list, "invalid_replay_cases")
    counts = {"matched": 0, "mismatched": 0, "failed": 0, "inconclusive": 0}
    if r["compilation"]["status"] != "succeeded":
        require(not r["cases"], "cases_without_compilation")
        category = "attack_failed" if r["compilation"]["status"] == "candidate_rejected" else "inconclusive"
    else:
        require(len(r["cases"]) == len(oracle["cases"]), "incomplete_replay_cases")
        for observed, expected in zip(r["cases"], oracle["cases"]):
            exact(observed, "id status value")
            require(observed["id"] == expected["id"], "replay_case_mismatch")
            require(observed["status"] in ("returned", "timeout", "crash", "infrastructure_failure", "not_run"),
                    "invalid_case_status")
            if observed["status"] == "returned":
                integer(observed["value"], 0, 2**32 - 1)
                counts["matched" if observed["value"] == expected["expected"] else "mismatched"] += 1
            else:
                require(observed["value"] is None, "unexpected_case_value")
                counts["inconclusive" if observed["status"] in ("infrastructure_failure", "not_run") else "failed"] += 1
        category = ("inconclusive" if counts["inconclusive"] else
                    "behavioral_suite_mismatch" if counts["mismatched"] else
                    "attack_failed" if counts["failed"] else "behavioral_suite_match")
    return {"classification": category, "origin": "explicitly_trusted_external_replay_receipt",
            "verifier_id": r["verifier_id"], "case_counts": counts,
            "independence": "operator_trust_anchor_not_inferred_from_file_contents",
            "scope": "this_candidate_this_finite_oracle_only", "security_property": "not_established"}


def verify_record(record, record_root, manifest, artifact_root, *, trusted_receipts=(), now=None):
    now = now or utcnow()
    oracle = validate_manifest(manifest, artifact_root, now)
    e = record
    exact(e, "schema comparison_sha256 artifact_id artifact_sha256 targets controls recorded_at kind source prompt candidate")
    require(e["schema"] == SCHEMA and e["kind"] in KINDS, "unsupported_evidence")
    require(e["comparison_sha256"] == identity(manifest), "evidence_comparison_mismatch")
    require(e["targets"] == manifest["targets"], "evidence_target_mismatch")
    validate_controls(e["controls"])
    require(e["controls"] == manifest["attacker_controls"], "noncomparable_attacker_configuration")
    observed = timestamp(e["recorded_at"])
    require(timestamp(manifest["created_at"]) <= observed <= now and observed <= timestamp(manifest["valid_until"]),
            "stale_or_future_evidence")
    matches = [a for a in manifest["artifacts"] if a["id"] == e["artifact_id"]]
    require(len(matches) == 1, "evidence_artifact_unknown")
    a = matches[0]
    require(a["file"]["sha256"] == e["artifact_sha256"], "evidence_artifact_mismatch")
    raw = checked(record_root, e["source"], MAX_JSON)
    context = None if e["prompt"] is None else check_context(record_root, e["prompt"], manifest, a, oracle)
    if e["kind"] in ("nemotron_summary", "lab_experiment", "behavioral_receipt"):
        require(context is not None, "missing_comparable_prompt")
    if e["kind"] == "behavioral_receipt":
        require(e["candidate"] is not None, "missing_candidate_binding")
        result = behavioral_receipt(raw, record_root, e, manifest, a, oracle, set(trusted_receipts))
    else:
        require(e["candidate"] is None, "unexpected_candidate")
        if e["kind"] == "ghidra":
            require("ghidra_decompilation" in e["controls"]["capabilities"], "capability_not_permitted")
            result = ghidra_observation(raw, manifest, a, context)
        elif e["kind"] == "rea":
            require("rea_reasoning" in e["controls"]["capabilities"], "capability_not_permitted")
            result = rea_observation(raw, record_root, manifest, a, context)
        elif e["kind"] == "nemotron_summary":
            require("rea_reasoning" in e["controls"]["capabilities"], "capability_not_permitted")
            result = nemotron_observation(raw, manifest, a, context)
        else:
            require("rea_reasoning" in e["controls"]["capabilities"], "capability_not_permitted")
            result = lab_experiment(raw, contained(record_root, e["source"]["path"]).parent, manifest, a, context,
                                    e["recorded_at"])
    return {"schema": "aegis.reconstruction.import-result.v1", "evidence_sha256": identity(e),
            "source_sha256": digest(raw), "comparison_sha256": identity(manifest),
            "artifact_id": a["id"], "artifact_sha256": a["file"]["sha256"], "kind": e["kind"],
            "recorded_at": e["recorded_at"], "prompt_binding": "checked" if context else "not_applicable",
            "freshness": "wrapper_timestamp_operator_declared_source_has_no_attested_clock",
            **result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("wrap", help="create a sidecar; always verifies before writing")
    p.add_argument("--comparison", type=Path, required=True)
    p.add_argument("--artifact-id", required=True)
    p.add_argument("--kind", choices=KINDS, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--controls", type=Path, required=True, help="actual predeclared experiment controls")
    p.add_argument("--recorded-at", required=True)
    p.add_argument("--prompt", type=Path, help="JSON containing four file references")
    p.add_argument("--candidate", type=Path)
    p.add_argument("--output", type=Path, required=True, help="new sidecar in the evidence archive root")
    p.add_argument("--trust-receipt", action="append", default=[], help="reviewer-supplied receipt SHA-256")
    p = sub.add_parser("verify", help="re-read files and recheck imports; never executes anything")
    p.add_argument("record", type=Path)
    p.add_argument("--comparison", type=Path, required=True)
    p.add_argument("--trust-receipt", action="append", default=[])
    p.add_argument("--as-of", help="explicit retrospective UTC time")
    p.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = load(args.comparison)
        for value in args.trust_receipt:
            sha(value)
        if args.command == "wrap":
            root = args.output.parent.resolve()
            matches = [a for a in manifest["artifacts"] if a["id"] == args.artifact_id]
            require(len(matches) == 1, "evidence_artifact_unknown")
            def ref(path):
                return reference(root, Path(path).absolute())
            record = {"schema": SCHEMA, "comparison_sha256": identity(manifest), "artifact_id": args.artifact_id,
                "artifact_sha256": matches[0]["file"]["sha256"], "targets": manifest["targets"],
                "controls": load(args.controls), "recorded_at": args.recorded_at, "kind": args.kind,
                "source": ref(args.source), "prompt": load(args.prompt) if args.prompt else None,
                "candidate": ref(args.candidate) if args.candidate else None}
            result = verify_record(record, root, manifest, args.comparison.parent, trusted_receipts=args.trust_receipt)
            write_json(args.output, record)
        else:
            result = verify_record(load(args.record), args.record.parent, manifest, args.comparison.parent,
                trusted_receipts=args.trust_receipt, now=timestamp(args.as_of) if args.as_of else None)
            if args.output:
                write_json(args.output, result)
        print(result["classification"] + " " + result["source_sha256"])
    except (Invalid, OSError, KeyError, TypeError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Invalid) else "invalid_input_or_environment", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
