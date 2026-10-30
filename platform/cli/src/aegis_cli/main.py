"""`aegis` CLI: init, inspect, protect, report, verify, evaluate.

Exit codes:
    0  success (verify: every output verified; evaluate: action permitted)
    1  the job ran and failed, the platform health check is degraded, an output
       is not verified, an action is denied, or stored bytes changed
    2  invalid usage or request
    3  configuration error (missing, invalid, already exists) or storage error
    4  unsupported backend or task
    5  authorization required
    6  job or input not found
    7  job conflict or report not ready
    70 internal error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from aegis_core import __version__
from aegis_core.config import (
    DEFAULT_CONFIG_NAME,
    AegisConfig,
    default_config_text,
    load_config,
    resolve_config_path,
)
from aegis_core.errors import AegisError
from aegis_core.health import check_health
from aegis_core.models import (
    AttackLabAuthorization,
    ErrorCode,
    JobStatus,
    ProtectionJob,
    ProtectionPolicy,
    ProtectionReport,
    TaskKind,
)
from aegis_core.orchestrator import Orchestrator
from aegis_provenance.jobs import JobAttestationStatus, JobAttestor
from aegis_sentinel.models import PermissionAction

CLI_CALLER_ID = "aegis-cli"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_UNSUPPORTED = 4
EXIT_AUTHORIZATION = 5
EXIT_NOT_FOUND = 6
EXIT_CONFLICT = 7
EXIT_INTERNAL = 70

EXIT_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.INVALID_REQUEST: EXIT_USAGE,
    ErrorCode.CONFIG_NOT_FOUND: EXIT_CONFIG,
    ErrorCode.CONFIG_INVALID: EXIT_CONFIG,
    ErrorCode.CONFIG_EXISTS: EXIT_CONFIG,
    ErrorCode.STORAGE_ERROR: EXIT_CONFIG,
    ErrorCode.UNSUPPORTED_BACKEND: EXIT_UNSUPPORTED,
    ErrorCode.UNSUPPORTED_TASK: EXIT_UNSUPPORTED,
    ErrorCode.AUTHORIZATION_REQUIRED: EXIT_AUTHORIZATION,
    ErrorCode.JOB_NOT_FOUND: EXIT_NOT_FOUND,
    ErrorCode.INPUT_NOT_FOUND: EXIT_NOT_FOUND,
    ErrorCode.INPUT_TOO_LARGE: EXIT_USAGE,
    ErrorCode.JOB_CONFLICT: EXIT_CONFLICT,
    ErrorCode.REPORT_NOT_READY: EXIT_CONFLICT,
    ErrorCode.ARTIFACT_NOT_FOUND: EXIT_NOT_FOUND,
    ErrorCode.POLICY_DENIED: EXIT_AUTHORIZATION,
    ErrorCode.ARTIFACT_INTEGRITY_ERROR: EXIT_FAILED,
}


# ------------------------------------------------------------------- output


def _emit_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=False))


def _fail(exc: AegisError, as_json: bool) -> int:
    info = exc.to_info()
    if as_json:
        _emit_json({"error": info.model_dump(mode="json")})
    else:
        print(f"error[{info.code.value}]: {info.message}", file=sys.stderr)
        for key, value in info.details.items():
            if key != "errors":
                print(f"  {key}: {value}", file=sys.stderr)
        for problem in info.details.get("errors", []):
            print(f"  - {problem.get('loc', '')}: {problem.get('msg', '')}", file=sys.stderr)
    return EXIT_BY_CODE.get(info.code, EXIT_INTERNAL)


def _print_job(job: ProtectionJob) -> None:
    print(f"job {job.job_id}: {job.status.value}")
    print(f"  backend: {job.policy.backend}  task: {job.policy.task.value}")
    print(f"  input:   {job.input_artifact.name}  sha256={job.input_artifact.sha256}")
    for artifact in job.output_artifacts:
        print(f"  output:  {artifact.name}  sha256={artifact.sha256}")
    if job.error is not None:
        print(f"  error:   {job.error.code.value}: {job.error.message}")
    if job.status.is_terminal:
        print(f"  report:  aegis report {job.job_id}")


def _print_report(report: ProtectionReport) -> None:
    print(f"AEGIS report {report.report_id}")
    print(f"  job:       {report.job_id}")
    print(f"  status:    {report.status.value}")
    print(f"  backend:   {report.policy.backend}  task: {report.policy.task.value}")
    print(f"  summary:   {report.summary}")
    print(f"  input:     {report.input_artifact.name}  sha256={report.input_artifact.sha256}")
    for artifact in report.output_artifacts:
        print(f"  output:    {artifact.name}  sha256={artifact.sha256}")
    if report.error is not None:
        print(f"  error:     {report.error.code.value}: {report.error.message}")
    if report.attack_evaluations:
        print("  attack evaluations:")
        for ev in report.attack_evaluations:
            print(f"    - {ev.attack}: {ev.outcome.value}")
    print(f"  evidence:  {len(report.evidence)} record(s)")
    for record in report.evidence:
        print(f"    - [{record.source.value}] {record.kind.value}: {record.summary}")
    print("  limitations:")
    for line in report.limitations:
        print(f"    - {line}")


def _print_attestation(status: JobAttestationStatus) -> None:
    print(f"  signing:   {status.signing.state}: {status.signing.message}")
    print(f"  sentinel:  {status.sentinel.state}: {status.sentinel.message}")
    for item in status.artifacts:
        sig = item.signature
        label = sig.status.upper()
        if sig.error_code:
            label += f" [{sig.error_code}]"
        print(f"  output:    {item.name}  sha256={item.sha256}")
        print(f"    signature: {label}: {sig.message}")
        if sig.key_id:
            print(f"    key id:    {sig.key_id}")
        pol = item.policy
        if pol.status == "valid":
            allowed = ",".join(p.action.value for p in pol.permissions if p.allowed) or "none"
            mode = pol.enforcement_mode.value if pol.enforcement_mode else "?"
            print(f"    policy:    valid {mode}; allowed: {allowed}")
        else:
            print(f"    policy:    {pol.status}" + (f": {'; '.join(pol.errors)}" if pol.errors else ""))


# ----------------------------------------------------------------- commands


def _load(args: argparse.Namespace) -> AegisConfig:
    return load_config(resolve_config_path(args.config))


def _orchestrator(config: AegisConfig) -> tuple[Orchestrator, JobAttestor]:
    """Orchestrator with output signing / Sentinel policies wired in when configured.

    A broken signing configuration raises CONFIG_INVALID (exit 3) before any job runs.
    """
    orchestrator = Orchestrator(config)
    attestor = JobAttestor.from_config(config, orchestrator.store, clock=orchestrator.clock)
    orchestrator.post_success_hooks.append(attestor.attest)
    return orchestrator, attestor


def cmd_init(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    path = Path(args.config) if args.config else directory / DEFAULT_CONFIG_NAME
    if path.exists() and not args.force:
        raise AegisError(
            ErrorCode.CONFIG_EXISTS,
            f"{path} already exists; pass --force to overwrite it.",
            {"path": str(path)},
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config_text(), encoding="utf-8")
    config = load_config(path)
    Orchestrator(config).store.initialize()
    if args.json:
        _emit_json({"config_path": str(path), "storage_root": str(config.storage.root)})
    else:
        print(f"wrote {path}")
        print(f"artifact store: {config.storage.root}")
        print("no protection backends are registered yet; add one under [adapters.<name>].")
    return EXIT_OK


def cmd_inspect(args: argparse.Namespace) -> int:
    config = _load(args)
    if args.job_id:
        job = Orchestrator(config).get_job(args.job_id)
        if args.json:
            _emit_json(job.model_dump(mode="json"))
        else:
            _print_job(job)
        return EXIT_OK

    health = check_health(config)
    if args.json:
        _emit_json(
            {
                **health.model_dump(mode="json"),
                "config_path": str(config.source_path) if config.source_path else None,
            }
        )
    else:
        print(f"AEGIS {health.version}: {health.status}")
        print(f"  config:     {config.source_path}")
        print(f"  storage:    {health.storage_root} (writable: {health.storage_writable})")
        print(f"  attack lab: {'enabled' if health.attack_lab_enabled else 'disabled'}")
        if not health.backends:
            print("  backends:   none registered")
        for backend in health.backends:
            tasks = ",".join(t.value for t in backend.tasks)
            state = "available" if backend.available else "UNAVAILABLE"
            print(f"  backend:    {backend.name} [{tasks}] {state}")
        for problem in health.problems:
            print(f"  problem:    {problem}")
    return EXIT_OK if health.status == "ok" else EXIT_FAILED


def _parse_option(raw: str) -> tuple[str, Any]:
    key, sep, value = raw.partition("=")
    if not sep or not key:
        raise AegisError(ErrorCode.INVALID_REQUEST, f"--option expects KEY=VALUE, got {raw!r}.")
    try:
        parsed = json.loads(value)
    except ValueError:
        return key, value
    if isinstance(parsed, (bool, int, float, str)):
        return key, parsed
    return key, value


def _build_policy(args: argparse.Namespace) -> ProtectionPolicy:
    task = TaskKind.ATTACK_LAB if args.task == "attack-lab" else TaskKind.PROTECT
    auth_fields = (args.authorized_by, args.authorization_ref, args.authorization_scope)
    authorization = None
    if any(auth_fields):
        if task is not TaskKind.ATTACK_LAB:
            raise AegisError(
                ErrorCode.INVALID_REQUEST,
                "Authorization flags only apply to --task attack-lab.",
            )
        if not all(auth_fields):
            raise AegisError(
                ErrorCode.AUTHORIZATION_REQUIRED,
                "Attack-lab authorization needs --authorized-by, --authorization-ref "
                "and --authorization-scope.",
            )
    try:
        if all(auth_fields):
            authorization = AttackLabAuthorization(
                authorized_by=args.authorized_by,
                reference=args.authorization_ref,
                scope=args.authorization_scope,
            )
        return ProtectionPolicy(
            name=args.policy_name,
            backend=args.backend,
            task=task,
            options=dict(_parse_option(o) for o in args.option),
            timeout_seconds=args.timeout,
            authorization=authorization,
        )
    except ValidationError as exc:
        problems = [
            {"loc": ".".join(str(p) for p in err["loc"]), "msg": err["msg"]}
            for err in exc.errors(include_input=False, include_url=False)
        ]
        raise AegisError(
            ErrorCode.INVALID_REQUEST, "Invalid protection policy.", {"errors": problems}
        ) from None


def cmd_protect(args: argparse.Namespace) -> int:
    config = _load(args)
    policy = _build_policy(args)
    orchestrator, attestor = _orchestrator(config)
    job = orchestrator.submit(policy, source=Path(args.input))
    job = orchestrator.run(job.job_id)
    if args.json:
        _emit_json(job.model_dump(mode="json"))
    else:
        _print_job(job)
        if job.status is JobStatus.SUCCEEDED:
            _print_attestation(attestor.status(job))
            print(f"  verify:  aegis verify {job.job_id}")
    return EXIT_OK if job.status is JobStatus.SUCCEEDED else EXIT_FAILED


def cmd_verify(args: argparse.Namespace) -> int:
    config = _load(args)
    orchestrator, attestor = _orchestrator(config)
    status = attestor.status(orchestrator.get_job(args.job_id))
    if args.json:
        _emit_json(status.model_dump(mode="json", by_alias=True))
    else:
        print(f"job {status.job_id}: {status.job_status.value}")
        _print_attestation(status)
        print(f"  result:    {'ALL OUTPUTS VERIFIED' if status.all_verified else 'NOT VERIFIED'}")
        print("  limitations:")
        for line in status.limitations:
            print(f"    - {line}")
    return EXIT_OK if status.all_verified else EXIT_FAILED


def cmd_evaluate(args: argparse.Namespace) -> int:
    config = _load(args)
    orchestrator, attestor = _orchestrator(config)
    job, artifact = orchestrator.find_output(args.job_id, args.sha256)
    decision = attestor.evaluate(
        job,
        artifact,
        PermissionAction(args.action),
        caller_id=args.caller_id,
        environment=args.environment,
    )
    if args.json:
        _emit_json(decision.model_dump(mode="json", by_alias=True))
    else:
        verdict = "PERMITTED" if decision.permitted else "DENIED"
        print(f"{verdict}: {decision.action.value} on {artifact.name} ({decision.enforcement_mode.value})")
        print(f"  reason: {decision.reason}")
        print("  caller and environment identifiers are asserted, not authenticated")
    return EXIT_OK if decision.permitted else EXIT_FAILED


def cmd_report(args: argparse.Namespace) -> int:
    config = _load(args)
    report = Orchestrator(config).get_report(args.job_id)
    payload = report.model_dump_json(indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    if args.json:
        print(payload)
    elif not args.output:
        _print_report(report)
    else:
        print(f"wrote report for job {report.job_id} to {args.output}")
    return EXIT_OK if report.status is JobStatus.SUCCEEDED else EXIT_FAILED


# ------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", help=f"path to {DEFAULT_CONFIG_NAME} (default: $AEGIS_CONFIG or ./aegis.toml)"
    )
    common.add_argument("--json", action="store_true", help="machine-readable JSON output")

    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS protection orchestrator.")
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", parents=[common], help="create aegis.toml and the local store")
    p_init.add_argument("--dir", default=".", help="directory for aegis.toml (default: .)")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing config")
    p_init.set_defaults(func=cmd_init)

    p_inspect = sub.add_parser(
        "inspect", parents=[common], help="show a job's status, or platform health without a job id"
    )
    p_inspect.add_argument("job_id", nargs="?")
    p_inspect.set_defaults(func=cmd_inspect)

    p_protect = sub.add_parser("protect", parents=[common], help="run a protection job")
    p_protect.add_argument("input", help="input artifact file")
    p_protect.add_argument("--backend", required=True, help="registered backend name")
    p_protect.add_argument("--task", choices=["protect", "attack-lab"], default="protect")
    p_protect.add_argument("--policy-name", default="default")
    p_protect.add_argument(
        "--option", action="append", default=[], metavar="KEY=VALUE",
        help="adapter option; JSON scalars (true, 3, 1.5) are typed, anything else is a string",
    )
    p_protect.add_argument("--timeout", type=int, help="override adapter timeout (seconds)")
    auth = p_protect.add_argument_group("attack-lab authorization (required for --task attack-lab)")
    auth.add_argument("--authorized-by", help="person or role granting authorization")
    auth.add_argument("--authorization-ref", help="engagement / ticket / approval id")
    auth.add_argument("--authorization-scope", help="what the authorization covers")
    p_protect.set_defaults(func=cmd_protect)

    p_report = sub.add_parser("report", parents=[common], help="show a finished job's report")
    p_report.add_argument("job_id")
    p_report.add_argument("--output", help="also write the JSON report to this file")
    p_report.set_defaults(func=cmd_report)

    p_verify = sub.add_parser(
        "verify",
        parents=[common],
        help="verify a job's signed outputs and Sentinel policies (exit 0 only if all verified)",
    )
    p_verify.add_argument("job_id")
    p_verify.set_defaults(func=cmd_verify)

    p_eval = sub.add_parser(
        "evaluate",
        parents=[common],
        help="ask a job output's Sentinel policy whether an action is permitted",
    )
    p_eval.add_argument("job_id")
    p_eval.add_argument("sha256", help="SHA-256 of a registered output artifact")
    p_eval.add_argument("--action", required=True, choices=[a.value for a in PermissionAction])
    p_eval.add_argument("--caller-id", help="asserted caller id (not authenticated)")
    p_eval.add_argument("--environment", help="asserted environment (not authenticated)")
    p_eval.set_defaults(func=cmd_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AegisError as exc:
        return _fail(exc, args.json)
    except OSError as exc:
        return _fail(AegisError(ErrorCode.STORAGE_ERROR, f"I/O error: {exc}"), args.json)
    except Exception as exc:
        return _fail(
            AegisError(ErrorCode.INTERNAL_ERROR, f"Unexpected error ({type(exc).__name__})."),
            args.json,
        )


if __name__ == "__main__":
    raise SystemExit(main())
