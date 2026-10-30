#!/usr/bin/env python3
"""AEGIS Evaluate: bind a live NVIDIA Nemotron reconstruction trial to a real Core protection job.

This is a thin product command over the existing Lab pipeline; it adds no inference code.

  prepare  Core job (succeeded, llvm-shield or llvm-shield-mirage, owned ImageLab kernels IR)
           -> rebuild ImageLab from the job's verified protected.ll (CTest must pass)
           -> fresh Ghidra 12.1.4 evidence for the baseline and protected executables
           -> manifests + unapproved approval drafts (aegis_lab.live draft) + binding record.
           No network, no credential, no approval consumed.
  run      after the operator saved a reviewed approval.json: offline preflight, then
           `python -m aegis_lab.live run` with the credential read from an operator-owned
           0600 file straight into the child environment (never printed or archived),
           then offline archive verification + public summary + binding update.
  score    behavioral scoring of a generated candidate WITHOUT host execution: the candidate is
           compiled freestanding to an import-free wasm32 module and run against hidden cases
           computed from the trusted owned kernel. Recorded separately from the Lab record.

Only AEGIS-owned ImageLab code is disclosed. Generated code never runs natively.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGELAB = ROOT / "demo/image_processor"
FUNCTION = "imagelab_color_adjust_pixel"
INTERFACE = "opaque(uint32_t,uint32_t,uint32_t,uint32_t)->uint32_t"
MODEL = "nvidia/Nemotron-3_5-Lightning"
BINDING = "aegis.evaluate.live-binding.v1"


class EvaluateError(ValueError):
    """Fixed reason codes only; never file contents or secrets."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, **kw):
    return subprocess.run([str(a) for a in argv], check=True, **kw)


def kernels_input_ll(work: Path) -> Path:
    """ImageLab's own protector-input recipe (see demo/image_processor/CMakeLists.txt)."""
    work.mkdir(parents=True, exist_ok=True)
    run(["clang++", "-std=c++20", "-O0", "-Xclang", "-disable-O0-optnone", "-Iinclude", "-S", "-emit-llvm",
         "src/kernels.cpp", "-o", work / "kernels.frontend.ll"], cwd=IMAGELAB)
    run(["opt", "-passes=function(sroa),verify", "-S", "kernels.frontend.ll", "-o", "kernels.input.ll"], cwd=work)
    return work / "kernels.input.ll"


def load_job(config_path: Path, job_id: str):
    from aegis_core.config import load_config
    from aegis_core.orchestrator import Orchestrator
    from aegis_provenance.jobs import JobAttestor
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    job = orchestrator.get_job(job_id)
    if job.status.value != "succeeded":
        raise EvaluateError("job_not_succeeded")
    if job.policy.backend not in ("llvm-shield", "llvm-shield-mirage"):
        raise EvaluateError("unsupported_backend")
    outputs = {a.name: a for a in job.output_artifacts}
    paths = {}
    for name in ("protected.ll", "shield-report.json", "mirage-report.json"):
        if name in outputs:
            path = orchestrator.store.artifact_path(outputs[name])
            if sha256_file(path) != outputs[name].sha256:
                raise EvaluateError("artifact_integrity_error")
            paths[name] = path
    attestation = JobAttestor.from_config(config, orchestrator.store, clock=orchestrator.clock).status(job)
    signatures = sorted({a.signature.status for a in attestation.artifacts}) if attestation.artifacts else []
    return job, outputs, paths, {"signing_state": attestation.signing.state, "signature_statuses": signatures}


def prepare(args) -> int:
    from aegis_lab.canonical import canonical_json_bytes, canonical_sha256
    from aegis_lab.evidence import parse_ghidra_report, planned_ghidra_tool
    from aegis_lab.ghidra import analyze
    from aegis_lab.manifest import TrialManifest
    from aegis_lab.reconstruction import planned_attack_digests
    from aegis_lab.safe_io import publish_new_file, read_regular_file

    if not args.authorized_owned_artifacts:
        raise EvaluateError("owned_artifact_authorization_required")
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    job, outputs, paths, attestation = load_job(args.config, args.job)
    if "verified" not in attestation["signature_statuses"] or attestation["signature_statuses"] != ["verified"]:
        if not args.allow_unsigned:
            raise EvaluateError("job_outputs_not_signature_verified")
    # The job must have protected exactly ImageLab's owned kernels as built from this checkout.
    fresh_input = kernels_input_ll(work / "ir")
    if sha256_file(fresh_input) != job.input_artifact.sha256:
        raise EvaluateError("job_input_is_not_owned_imagelab_kernels")
    build = work / "imagelab"
    run(["cmake", "-S", IMAGELAB, "-B", build, "-G", "Ninja", "-DCMAKE_CXX_COMPILER=clang++",
         "-DCMAKE_BUILD_TYPE=Release", "-DIMAGELAB_ENABLE_IR_VARIANTS=ON",
         f"-DIMAGELAB_EXTERNAL_KERNELS_IR={paths['protected.ll']}"], stdout=subprocess.DEVNULL)
    run(["cmake", "--build", build], stdout=subprocess.DEVNULL)
    run(["ctest", "--test-dir", build, "--output-on-failure"], stdout=subprocess.DEVNULL)
    variants = json.loads((build / "imagelab-variants.json").read_text())
    shield_report = json.loads(paths["shield-report.json"].read_text())
    mirage_report = json.loads(paths["mirage-report.json"].read_text()) if "mirage-report.json" in paths else None
    compiler = Path(variants["compiler"]).resolve()
    conditions = {"pipeline": "aegis-core-job-imagelab-ir-build",
        "compiler": {"name": "clang", "version": variants["compiler_version"],
            "executable_sha256": sha256_file(compiler),
            "configuration_sha256": canonical_sha256({"flags": variants["ir_backend_flags"], "build_type": variants["build_type"]})},
        "shared_recipe_sha256": canonical_sha256({"compiler": variants["compiler_version"],
            "ir_backend_flags": variants["ir_backend_flags"], "build_type": variants["build_type"],
            "recipe": "ImageLab IR variants; protected variant from a Core job output"}),
        "symbols": "present", "debug_info": False}
    tool = planned_ghidra_tool(args.ghidra_headless, function="*", max_functions=512)
    pair_id = secrets.token_hex(16)
    adapter_script = ROOT / "protectors/llvm/adapter" / (
        "aegis_shield_mirage_adapter.py" if job.policy.backend == "llvm-shield-mirage" else "aegis_llvm_adapter.py")
    targets = {}
    for name, directory in (("baseline", "ir-baseline"), ("protected", "external")):
        root = work / name
        root.mkdir(mode=0o700)
        artifact = build / directory / "imagelab-cli"
        digest = sha256_file(artifact)
        report_path = analyze(artifact, root / "ghidra", args.ghidra_headless, function="*", max_functions=512,
                              expected_sha256=digest, expected_ghidra_version="12.1.4")
        report_path.parent.chmod(0o700)
        report = parse_ghidra_report(read_regular_file(report_path, 8 * 1024 * 1024))
        protection = None
        if name == "protected":
            protection = {"backend": {"name": job.policy.backend, "version": f"aegis-core-job-{job.job_id}",
                "executable_sha256": sha256_file(adapter_script),
                "configuration_sha256": canonical_sha256({"options": job.policy.options})}, "seed": 42,
                "transformation_report_sha256": outputs["shield-report.json"].sha256}
        manifest = TrialManifest.model_validate({"trial_id": secrets.token_hex(16), "pair_id": pair_id,
            "variant": "baseline" if name == "baseline" else "protected",
            "target": {"name": "operator-owned-imagelab", "function": FUNCTION, "source_revision": args.source_revision,
                "platform": "linux-x86_64", "artifact_format": "ELF", "final_artifact_sha256": digest,
                "build": conditions, "protection": protection},
            "attack": {"workflow": "ghidra_model", "tools": [tool.model_dump(mode="json")], "provider": "Nebius",
                "model_id": args.model, "sampling_seed": None, "temperature": 0.0,
                "session_isolation": "fresh_session_and_workspace",
                **planned_attack_digests(max_model_tokens=args.max_model_tokens, blinded=True,
                                         max_output_tokens=args.max_output_tokens,
                                         enable_thinking=False if args.disable_thinking else None)},
            "access": {"workspace_policy_sha256": canonical_sha256({"scope": "bound decompilation only; no source, hidden tests or oracle"})},
            "budget": {"max_wall_seconds": 240, "max_model_tokens": args.max_model_tokens, "max_tool_calls": 8, "max_attempts": 1},
            "scoring": {"hidden_test_suite_sha256": canonical_sha256({"status": "scored_separately_by_live_evaluate_score"}),
                "scorer": {"name": "not-configured", "version": "lab-record-unscored",
                    "executable_sha256": canonical_sha256({"scorer": "absent"}),
                    "configuration_sha256": canonical_sha256({"execution": False})}, "expected_interface": INTERFACE},
            "authorization": {"reference": "operator-owned-artifact-static-analysis",
                "authorized_scope": "local Ghidra preparation only; external inference requires separate operator approval"}})
        manifest_path = root / "manifest.json"
        publish_new_file(manifest_path, manifest.canonical_bytes(), 1024 * 1024)
        run([sys.executable, "-m", "aegis_lab.live", "draft", manifest_path, report_path, artifact,
             "--max-output-tokens", args.max_output_tokens, "--steps", 1, "--context-tokens", args.context_tokens,
             "--input-microusd-per-million", args.input_microusd_per_million,
             "--output-microusd-per-million", args.output_microusd_per_million,
             "--max-spend-microusd", args.max_spend_microusd, "--request-timeout", 120,
             "--output", root / "approval.DRAFT.json",
             *(["--disable-thinking"] if args.disable_thinking else [])], stdout=subprocess.DEVNULL)
        draft = json.loads((root / "approval.DRAFT.json").read_text())
        review = (root / "approval.DRAFT.json.request-review.json").read_bytes()
        names = {f.name for f in report.analysis.functions}
        decoys = sorted(set(mirage_report["inserted_functions"]) & names) if mirage_report else []
        selected = next(f for f in report.analysis.functions if f.name == FUNCTION)
        targets[name] = {"artifact": str(artifact), "artifact_sha256": digest, "manifest": str(manifest_path),
            "manifest_sha256": sha256_file(manifest_path), "ghidra_report": str(report_path),
            "ghidra_report_sha256": sha256_file(report_path), "ghidra_function_count": len(report.analysis.functions),
            "selected_decompilation_sha256": hashlib.sha256(selected.decompiled_c.encode()).hexdigest(),
            "decoys_in_ghidra_evidence": decoys,
            "decoys_in_model_request": sorted(d for d in decoys if d.encode() in review),
            "rendered_prompt_sha256": draft["disclosure"]["rendered_prompt_sha256"],
            "request_review_sha256": hashlib.sha256(review).hexdigest(), "request_review_bytes": len(review),
            "draft": str(root / "approval.DRAFT.json")}
    if targets["baseline"]["selected_decompilation_sha256"] == targets["protected"]["selected_decompilation_sha256"]:
        raise EvaluateError("protected_selected_decompilation_unchanged")
    binding = {"schema": BINDING, "created_at": datetime.now(UTC).isoformat(), "job_id": job.job_id,
        "backend": job.policy.backend, "job_options": job.policy.options,
        "job_input_sha256": job.input_artifact.sha256,
        "job_outputs": {n: a.sha256 for n, a in outputs.items()}, "attestation": attestation,
        "shield_transformed_sites": shield_report["transformed_sites"],
        "mirage_inserted_functions": mirage_report["inserted_count"] if mirage_report else 0,
        "imagelab_ctest": "passed", "model": args.model, "function": FUNCTION, "targets": targets,
        "enable_thinking": False if args.disable_thinking else None,
        "live_requests": 0, "candidate_execution": False,
        "notes": ["The model request discloses only the selected function's Ghidra decompilation.",
                  "Mirage decoys reach the model only if listed in decoys_in_model_request."]}
    publish_new_file(work / "binding.json", canonical_json_bytes(binding), 1024 * 1024)
    print(json.dumps({k: binding[k] for k in ("job_id", "backend", "attestation")} |
                     {"targets": {n: {k: t[k] for k in ("artifact_sha256", "rendered_prompt_sha256",
                                                        "decoys_in_ghidra_evidence", "decoys_in_model_request")}
                                  for n, t in targets.items()}}, indent=2))
    return 0


def approve(args) -> int:
    """Operator-only: review the exact request and save a fresh single-use approval.json.

    Refuses without an interactive terminal so that no agent or script can approve spending.
    """
    from datetime import timedelta
    from aegis_lab.canonical import canonical_json_bytes
    from aegis_lab.disclosure import InferenceApproval
    from aegis_lab.safe_io import publish_new_file
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise EvaluateError("approval_requires_interactive_operator_terminal")
    work = args.workdir.resolve()
    binding = json.loads((work / "binding.json").read_text())
    target = binding["targets"][args.target]
    draft_path = Path(target["draft"])
    draft = json.loads(draft_path.read_text())
    review = json.loads(Path(str(draft_path) + ".request-review.json").read_text())
    reserve = lab_reservation(draft, review["max_tokens"])
    if reserve > draft["max_spend_microusd"]:
        raise EvaluateError("draft_ceiling_below_lab_reservation")
    ledger = Path(args.budget_ledger) if args.budget_ledger else work.parent / "nvidia-budget-ledger.jsonl"
    committed = ledger_committed(ledger)
    print("=== AEGIS live NVIDIA evaluation: operator review ===")
    print(f"Core job            : {binding['job_id']} ({binding['backend']}), signatures {binding['attestation']}")
    print(f"Target              : {args.target} executable sha256 {target['artifact_sha256']}")
    print(f"Endpoint / model    : {draft['disclosure']['endpoint']}  {review['model']}")
    print(f"Request             : 1 POST, max_tokens {review['max_tokens']}, temperature {review.get('temperature')}, store {review.get('store')}")
    if "chat_template_kwargs" in review:
        print("Thinking options    : " + json.dumps(review["chat_template_kwargs"], sort_keys=True))
    print(f"Spend ceiling       : {draft['max_spend_microusd']} micro-USD (${draft['max_spend_microusd'] / 1e6:.6f})")
    print(f"Lab reservation     : {reserve} micro-USD (${reserve / 1e6:.6f}) = full {draft['context_tokens']} context at input price"
          f" + {review['max_tokens']} output tokens at output price; actual usage is billed by Nebius")
    print(f"Project budget      : ${committed / 1e6:.6f} of ${args.project_budget_microusd / 1e6:.2f} committed so far"
          f" (ledger {ledger}); admission requires committed + this ceiling ${draft['max_spend_microusd'] / 1e6:.2f}"
          f" <= budget; once started this run stays committed at ${reserve / 1e6:.6f}")
    if committed + draft["max_spend_microusd"] > args.project_budget_microusd:
        raise EvaluateError("project_budget_would_be_exceeded")
    print(f"Disclosed           : owned ImageLab function {binding['function']} (Ghidra decompilation only);")
    print(f"                      Mirage decoys in request: {target['decoys_in_model_request'] or 'none'}")
    print(f"Rendered prompt     : sha256 {target['rendered_prompt_sha256']}")
    print("--- exact request body (as it will be sent, minus nothing) ---")
    for message in review["messages"]:
        print(f"[{message['role']}]\n{message['content']}\n")
    print("--- end of request body ---")
    if input("Type the first 12 hex digits of the target sha256 to continue: ").strip() != target["artifact_sha256"][:12]:
        raise EvaluateError("operator_did_not_confirm_artifact")
    name = input("Your name or operator ID (recorded as approved_by): ").strip()
    retention = input("Retention terms you reviewed (short description, e.g. 'Nebius Token Factory terms reviewed 2026-10-30'): ").strip()
    if not name or not retention:
        raise EvaluateError("approval_fields_required")
    if input("Type APPROVE to authorize exactly one paid request under these limits: ").strip() != "APPROVE":
        raise EvaluateError("operator_declined")
    now = datetime.now(UTC)
    window = timedelta(minutes=args.window_minutes)
    approval = {**draft, "operator_approved": True, "provider_retention_reviewed": True,
                "provider_retention_policy": retention,
                "disclosure": {**draft["disclosure"], "approved_by": name,
                               "reference": f"aegis-live-evaluate:{binding['job_id']}:{args.target}:{now.strftime('%Y%m%dT%H%M%SZ')}",
                               "created_at": now.isoformat(), "valid_from": now.isoformat(),
                               "expires_at": (now + window).isoformat()},
                "request_deadline": (now + window).isoformat(),
                "private_archive_delete_after": (now + timedelta(days=args.retain_days)).isoformat()}
    InferenceApproval.model_validate(approval)
    out = work / args.target / f"approval-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    publish_new_file(out, canonical_json_bytes(approval), 64 * 1024)
    os.chmod(out, 0o600)
    print(f"Saved single-use approval: {out}")
    return 0


def ledger_committed(ledger: Path) -> int:
    """Committed spend: every started or historical paid request at its verified worst-case reservation.

    A request's possible charge is bounded by the Lab reservation (full published context at the input
    price plus max output at the output price, prices verified against the catalogue before disclosure);
    the approval ceiling is only a cap. Started requests stay committed even if they failed.
    """
    if not ledger.exists():
        return 0
    total = 0
    for line in ledger.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("event") in ("reserved", "historical"):
            total += int(entry.get("lab_reservation_microusd", entry.get("ceiling_microusd")))
    return total


def lab_reservation(approval: dict, max_output_tokens: int) -> int:
    from types import SimpleNamespace
    from aegis_lab.inference import worst_request_cost
    per_request = worst_request_cost(SimpleNamespace(**{k: approval[k] for k in (
        "context_tokens", "input_microusd_per_million", "output_microusd_per_million")}), max_output_tokens)
    return per_request * int(approval.get("max_requests", 1))


def ledger_append(ledger: Path, entry: dict) -> None:
    fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")


def read_credential(path: Path) -> str:
    """Operator-created secret file: regular, not a symlink, owned by us, mode 0600, outside the repository."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise EvaluateError("credential_file_must_be_private_regular_file")
    if Path(path).resolve().is_relative_to(ROOT.resolve()):
        raise EvaluateError("credential_file_inside_repository")
    value = Path(path).read_text().strip()
    if not value or any(c.isspace() for c in value) or len(value) > 4096:
        raise EvaluateError("credential_file_malformed")
    return value


def run_live(args) -> int:
    from aegis_lab.canonical import canonical_json_bytes
    from aegis_lab.safe_io import publish_new_file
    work = args.workdir.resolve()
    binding = json.loads((work / "binding.json").read_text())
    target = binding["targets"][args.target]
    if args.approval is None:
        # Exactly one operator-saved approval may exist for this target; a used one is refused by the Lab.
        found = sorted((work / args.target).glob("approval-*.json"))
        if len(found) != 1:
            raise EvaluateError("expected_exactly_one_saved_approval")
        args.approval = found[0]
    if (args.credential_file is None) == (not args.use_environment_credential):
        raise EvaluateError("choose_credential_file_or_environment")
    if args.use_environment_credential:
        secret = os.environ.get("NEBIUS_API_KEY", "")
        if not secret.strip():
            raise EvaluateError("credential_environment_variable_missing")
    else:
        secret = read_credential(args.credential_file)
    common = [target["manifest"], target["ghidra_report"], target["artifact"], "--max-output-tokens",
              str(args.max_output_tokens), "--steps", "1", "--approval", str(args.approval)]
    if getattr(args, "disable_thinking", False):
        common.append("--disable-thinking")
    pre = subprocess.run([sys.executable, "-m", "aegis_lab.live", "preflight", *common],
                         capture_output=True, text=True, env={k: v for k, v in os.environ.items() if k != "NEBIUS_API_KEY"})
    if pre.returncode:
        raise EvaluateError("preflight_failed")
    summary = json.loads(pre.stdout)
    if not summary["approval_validated"] or summary["candidate_execution_authorized"] or summary["proposed_model"] != binding["model"]:
        raise EvaluateError("preflight_not_approved")
    approval_record = json.loads(Path(args.approval).read_text())
    ledger = Path(args.budget_ledger) if args.budget_ledger else work.parent / "nvidia-budget-ledger.jsonl"
    committed = ledger_committed(ledger)
    ceiling = int(approval_record["max_spend_microusd"])
    reservation = lab_reservation(approval_record, args.max_output_tokens)
    if reservation > ceiling:
        raise EvaluateError("approval_ceiling_below_lab_reservation")
    if committed + ceiling > args.project_budget_microusd:
        raise EvaluateError("project_budget_would_be_exceeded")
    ledger_append(ledger, {"event": "reserved", "at": datetime.now(UTC).isoformat(), "job_id": binding["job_id"],
                           "target": args.target, "artifact_sha256": target["artifact_sha256"],
                           "approval_sha256": sha256_file(args.approval), "ceiling_microusd": ceiling,
                           "lab_reservation_microusd": reservation,
                           "committed_before_microusd": committed, "project_budget_microusd": args.project_budget_microusd})
    env = dict(os.environ)
    env["NEBIUS_API_KEY"] = secret
    del secret
    out_dir = work / f"live-{args.target}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    started = datetime.now(UTC).isoformat()
    live = subprocess.run([sys.executable, "-m", "aegis_lab.live", "run", *common, "--output-dir", str(out_dir),
                           "--approve-live-inference"], capture_output=True, text=True, env=env)
    del env
    result = {"schema": BINDING + ".run", "target": args.target, "job_id": binding["job_id"],
              "artifact_sha256": target["artifact_sha256"], "started_at": started,
              "finished_at": datetime.now(UTC).isoformat(), "exit_code": live.returncode,
              "runner_stdout": live.stdout.strip()[-2000:], "runner_stderr_code": live.stderr.strip()[-200:],
              "output_dir": str(out_dir), "approval_sha256": sha256_file(args.approval)}
    if (out_dir / "experiment.json").is_file():
        summary_path = out_dir.parent / f"{out_dir.name}-public-summary.json"
        exported = subprocess.run([sys.executable, str(ROOT / "scripts/export-product-evidence.py"), "reconstruction",
                                   str(out_dir), "--output", str(summary_path)], capture_output=True, text=True)
        result["export_exit_code"] = exported.returncode
        if exported.returncode == 0:
            result["public_summary"] = str(summary_path)
            result["public_summary_sha256"] = sha256_file(summary_path)
            result["public_summary_record"] = json.loads(summary_path.read_text())["summary"]
    experiment = out_dir / "experiment.json"
    if experiment.is_file():
        record = json.loads(experiment.read_text())
        result["generation_status"] = record.get("generation_status")
        candidate_sha = record.get("candidate_sha256")
        result["candidate_sha256"] = candidate_sha
        # Lab's approval authorizes inference only. A returned candidate must not
        # silently enter the separate compiler/executor through this command.
        result["candidate_scoring"] = {
            "status": "not_run", "reason": "inference_approval_does_not_authorize_candidate_execution"}
    usage = (result.get("public_summary_record") or {})
    ledger_append(ledger, {"event": "finished", "at": datetime.now(UTC).isoformat(), "job_id": binding["job_id"],
                           "target": args.target, "exit_code": live.returncode,
                           "reported_tokens": usage.get("reported_tokens"),
                           "estimated_reported_cost_microusd": usage.get("estimated_reported_cost_microusd"),
                           "reserved_spend_microusd": usage.get("reserved_spend_microusd")})
    result["project_budget"] = {"ledger": str(ledger), "committed_microusd_after": ledger_committed(ledger),
                                "project_budget_microusd": args.project_budget_microusd}
    publish_new_file(work / f"{out_dir.name}-binding.json", canonical_json_bytes(result), 1024 * 1024)
    print(json.dumps({k: v for k, v in result.items() if k != "public_summary_record"}, indent=2))
    return 0 if live.returncode == 0 else 1


def score(args) -> int:
    """Behavioral scoring of one candidate in an import-free wasm32 sandbox (never native execution)."""
    source = Path(args.candidate).read_bytes()
    with tempfile.TemporaryDirectory(prefix="aegis-score-") as tmp:
        tmp = Path(tmp)
        # Expected outputs from the trusted owned kernel, computed natively.
        ref = tmp / "ref.cpp"
        ref.write_text(REFERENCE_CPP)
        run(["clang++", "-std=c++20", "-O2", f"-I{IMAGELAB / 'include'}", ref, IMAGELAB / "src/kernels.cpp",
             "-o", tmp / "ref"])
        cases = tmp / "cases.txt"
        with cases.open("w") as stream:
            run([tmp / "ref"], stdout=stream)
        cand = tmp / "candidate.c"
        # The declared interface names uint32_t, so the harness supplies <stdint.h> before the
        # unmodified candidate text; nothing else is added except the exported entry point.
        cand.write_bytes(b"#include <stdint.h>\n" + source + b"\nuint32_t aegis_scored_entry(uint32_t a, uint32_t b, "
                         b"uint32_t c, uint32_t d) { return opaque(a, b, c, d); }\n")
        wasm = tmp / "candidate.wasm"
        built = subprocess.run(["clang", "--target=wasm32", "-std=c11", "-O2", "-nostdlib", "-ffreestanding",
                                "-fno-builtin", "-Wl,--no-entry", "-Wl,--export=aegis_scored_entry",
                                "-o", str(wasm), str(cand)], capture_output=True, text=True)
        record = {"schema": "aegis.evaluate.wasm-score.v1", "candidate_sha256": hashlib.sha256(source).hexdigest(),
                  "cases_sha256": sha256_file(cases), "cases": sum(1 for _ in cases.open()),
                  "sandbox": "wasm32 freestanding, zero imports, Node worker with heap limits and 60 s timeout",
                  "native_execution_of_candidate": False,
                  "harness_preamble": "#include <stdint.h>", "entry_point": "aegis_scored_entry -> opaque"}
        if built.returncode:
            record.update(status="candidate_build_failed")
        else:
            evaluator = tmp / "eval.mjs"
            evaluator.write_text(EVALUATOR_MJS)
            ran = subprocess.run(["node", str(evaluator), str(wasm), str(cases)], capture_output=True, text=True, timeout=120)
            record.update(json.loads(ran.stdout.strip().splitlines()[-1]))
    print(json.dumps(record, indent=2))
    if args.output:
        args.output.write_text(json.dumps(record, indent=2) + "\n")
    return 0


REFERENCE_CPP = r"""
#include <cstdint>
#include <cstdio>
extern "C" uint32_t imagelab_color_adjust_pixel(uint32_t, uint32_t, uint32_t, uint32_t);
static uint64_t s = 0x2545F4914F6CDD1DULL;
static uint64_t nx() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
int main() {
  const uint32_t P[] = {0, 1, 2, 127, 128, 255, 256, 257, 510, 511, 512, 1023, 1024, 1025, 4096, 0xFFFFFFFFu};
  const uint32_t X[] = {0u, 0xFFFFFFFFu, 0x00FF00FFu, 0x80808080u, 0x12345678u, 0xFF000000u, 0x0000FFFFu};
  for (uint32_t x : X) for (uint32_t a : P) for (uint32_t b : P) for (uint32_t c : P)
    printf("%u %u %u %u %u\n", x, a, b, c, imagelab_color_adjust_pixel(x, a, b, c));
  for (int i = 0; i < 100000; ++i) {
    uint32_t x = (uint32_t)nx(), a = (uint32_t)(nx() % 1200), b = (uint32_t)(nx() % 1200), c = (uint32_t)(nx() % 600);
    if (i % 10 == 0) { a = (uint32_t)nx(); b = (uint32_t)nx(); c = (uint32_t)nx(); }
    printf("%u %u %u %u %u\n", x, a, b, c, imagelab_color_adjust_pixel(x, a, b, c));
  }
}
"""

EVALUATOR_MJS = r"""
import { Worker } from "node:worker_threads";
import { readFileSync } from "node:fs";
const [wasmPath, casesPath] = process.argv.slice(2);
const bytes = readFileSync(wasmPath);
const imports = WebAssembly.Module.imports(new WebAssembly.Module(bytes));
if (imports.length) { console.log(JSON.stringify({ status: "rejected_imports", imports })); process.exit(0); }
const code = `const { parentPort, workerData } = require("node:worker_threads");
const f = new WebAssembly.Instance(new WebAssembly.Module(workerData.bytes), {}).exports.aegis_scored_entry;
let pass = 0, fail = 0, firstFail = null;
for (const line of workerData.cases) { const v = line.split(" ").map(Number); if (v.length < 5) continue;
  let got; try { got = f(v[0], v[1], v[2], v[3]) >>> 0; } catch (e) { got = "trap"; }
  if (got === v[4]) pass++; else { fail++; if (!firstFail) firstFail = { input: v.slice(0, 4), expected: v[4], got }; } }
parentPort.postMessage({ pass, fail, firstFail });`;
const w = new Worker(code, { eval: true, workerData: { bytes, cases: readFileSync(casesPath, "utf8").split("\n") },
  resourceLimits: { maxOldGenerationSizeMb: 256, maxYoungGenerationSizeMb: 32 }, env: {} });
const timer = setTimeout(() => { console.log(JSON.stringify({ status: "timeout" })); w.terminate(); process.exit(0); }, 60000);
w.on("message", m => { clearTimeout(timer); console.log(JSON.stringify({ status: m.fail ? "behaviorally_incorrect" : "behaviorally_verified_on_hidden_cases", imports: 0, ...m })); w.terminate(); });
w.on("error", e => { clearTimeout(timer); console.log(JSON.stringify({ status: "sandbox_error" })); process.exit(0); });
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--job", required=True)
    p.add_argument("--workdir", type=Path, required=True)
    p.add_argument("--ghidra-headless", type=Path, required=True)
    p.add_argument("--source-revision", required=True)
    p.add_argument("--model", default=MODEL)
    p.add_argument("--max-model-tokens", type=int, default=2_000_000)
    p.add_argument("--max-output-tokens", type=int, default=8192)
    p.add_argument("--disable-thinking", action="store_true", help="explicit approved request for enable_thinking=false; absent preserves provider default")
    p.add_argument("--context-tokens", type=int, default=1_048_576)
    p.add_argument("--input-microusd-per-million", type=int, default=60_000)
    p.add_argument("--output-microusd-per-million", type=int, default=240_000)
    p.add_argument("--max-spend-microusd", type=int, default=10_000_000)
    p.add_argument("--allow-unsigned", action="store_true")
    p.add_argument("--authorized-owned-artifacts", action="store_true")
    r = sub.add_parser("run")
    r.add_argument("--workdir", type=Path, required=True)
    r.add_argument("--target", choices=("baseline", "protected"), required=True)
    r.add_argument("--approval", type=Path, help="default: the single approval-*.json saved for this target")
    credential = r.add_mutually_exclusive_group(required=True)
    credential.add_argument("--credential-file", type=Path, help="operator-owned 0600 file outside the repository")
    credential.add_argument("--use-environment-credential", action="store_true",
                            help="use NEBIUS_API_KEY already set in this operator terminal (never printed)")
    r.add_argument("--max-output-tokens", type=int, default=8192)
    r.add_argument("--disable-thinking", action="store_true", help="must match the exact prepared and approved thinking option")
    r.add_argument("--budget-ledger", type=Path, help="default: <workdir>/../nvidia-budget-ledger.jsonl")
    r.add_argument("--project-budget-microusd", type=int, default=20_000_000, help="shared project cap ($20)")
    a = sub.add_parser("approve", help="operator-only, interactive")
    a.add_argument("--workdir", type=Path, required=True)
    a.add_argument("--target", choices=("baseline", "protected"), required=True)
    a.add_argument("--window-minutes", type=int, default=120)
    a.add_argument("--retain-days", type=int, default=7)
    a.add_argument("--budget-ledger", type=Path, help="default: <workdir>/../nvidia-budget-ledger.jsonl")
    a.add_argument("--project-budget-microusd", type=int, default=20_000_000, help="shared project cap ($20)")
    s = sub.add_parser("score")
    s.add_argument("candidate", type=Path)
    s.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        return {"prepare": prepare, "approve": approve, "run": run_live, "score": score}[args.command](args)
    except EvaluateError as exc:
        print(f"live_evaluate_failed: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError:
        print("live_evaluate_failed: subprocess_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
