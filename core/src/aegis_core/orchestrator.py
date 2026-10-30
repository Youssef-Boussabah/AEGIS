"""Local orchestrator: validates policies, stores artifacts, runs adapters, builds reports."""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapter import AdapterInvocation, AdapterRequest, SubprocessAdapterRunner
from .config import AdapterSpec, AegisConfig
from .errors import AegisError
from .lab_authorization import check_attack_lab_gates
from .models import (
    Artifact,
    ArtifactRole,
    AttackEvaluation,
    ErrorCode,
    EvidenceKind,
    EvidenceRecord,
    EvidenceSource,
    JobStatus,
    ProtectionJob,
    ProtectionPolicy,
    ProtectionReport,
    TaskKind,
    utcnow,
)
from .storage import LocalArtifactStore, sha256_file

logger = logging.getLogger(__name__)


def _new_id() -> str:
    return uuid.uuid4().hex


PostSuccessHook = Callable[[ProtectionJob], None]
"""Called with a succeeded job after its outputs are hashed and registered, before
the report and terminal job.json are written. It must not change the outputs. An
exception is logged and never turns the job into a failure: hooks record their
own outcome (for example aegis_provenance.jobs writes signing_failed)."""

MAX_OUTPUT_READ_BYTES = 256 * 1024 * 1024


class Orchestrator:
    def __init__(
        self,
        config: AegisConfig,
        *,
        store: LocalArtifactStore | None = None,
        runner: SubprocessAdapterRunner | None = None,
        clock: Callable[[], datetime] = utcnow,
        post_success_hooks: Sequence[PostSuccessHook] = (),
    ):
        self.config = config
        self.post_success_hooks: list[PostSuccessHook] = list(post_success_hooks)
        self.store = store or LocalArtifactStore(
            config.storage.root, max_input_bytes=config.storage.max_input_bytes
        )
        self.runner = runner or SubprocessAdapterRunner()
        self.clock = clock

    # ------------------------------------------------------------- validation

    def validate_policy(self, policy: ProtectionPolicy) -> AdapterSpec:
        """Return the adapter for a policy, or raise an explicit error."""
        spec = self.config.adapters.get(policy.backend)
        if spec is None:
            raise AegisError(
                ErrorCode.UNSUPPORTED_BACKEND,
                f"Backend {policy.backend!r} is not supported: no adapter is registered "
                "for it in the AEGIS configuration.",
                {"backend": policy.backend, "supported_backends": self.config.supported_backends()},
            )
        if policy.task not in spec.tasks:
            raise AegisError(
                ErrorCode.UNSUPPORTED_TASK,
                f"Backend {policy.backend!r} does not support task {policy.task.value!r}.",
                {"backend": policy.backend, "supported_tasks": [t.value for t in spec.tasks]},
            )
        if policy.task is TaskKind.ATTACK_LAB:
            self._check_attack_lab_authorization(policy)
        return spec

    def _check_attack_lab_authorization(self, policy: ProtectionPolicy) -> None:
        # One definition of the two gates, shared with candidate execution.
        check_attack_lab_gates(self.config, policy.authorization, self.clock())

    # ----------------------------------------------------------------- submit

    def submit(
        self,
        policy: ProtectionPolicy,
        *,
        source: Path | None = None,
        data: bytes | None = None,
        name: str | None = None,
    ) -> ProtectionJob:
        """Validate the policy, store the input and record a pending job."""
        self.validate_policy(policy)
        if name is None:
            name = source.name if source is not None else "input.bin"
        job_id = _new_id()
        try:
            self.store.create_job_dir(job_id)
        except OSError as exc:
            raise AegisError(
                ErrorCode.STORAGE_ERROR, f"Cannot create job directory: {exc.strerror}"
            ) from None
        try:
            artifact = self.store.ingest_input(job_id, name, source=source, data=data)
            now = self.clock()
            job = ProtectionJob(
                job_id=job_id,
                status=JobStatus.PENDING,
                policy=policy,
                input_artifact=artifact,
                created_at=now,
                updated_at=now,
            )
            self.store.save_job(job)
        except BaseException:
            self.store.remove_job_dir(job_id)
            raise
        return job

    # -------------------------------------------------------------------- run

    def run(self, job_id: str) -> ProtectionJob:
        """Execute a pending job to a terminal state. Always writes a report."""
        job = self.store.load_job(job_id)
        if job.status is not JobStatus.PENDING or not self.store.claim_job(job_id):
            raise AegisError(
                ErrorCode.JOB_CONFLICT,
                f"Job {job_id} is not pending (status: {job.status.value}).",
                {"status": job.status.value},
            )
        now = self.clock()
        job = _evolve(job, status=JobStatus.RUNNING, started_at=now, updated_at=now)
        self.store.save_job(job)

        evidence: list[EvidenceRecord] = []
        evaluations: list[AttackEvaluation] = []
        try:
            outputs = self._execute(job, evidence, evaluations)
            now = self.clock()
            job = _evolve(
                job,
                status=JobStatus.SUCCEEDED,
                output_artifacts=[a.model_dump() for a in outputs],
                updated_at=now,
                finished_at=now,
            )
        except AegisError as exc:
            evaluations.clear()
            job = self._failed(job, exc)
        except Exception as exc:  # never leave a job stuck in "running"
            logger.exception("unexpected error while running job %s", job_id)
            evaluations.clear()
            job = self._failed(
                job,
                AegisError(
                    ErrorCode.INTERNAL_ERROR,
                    f"Unexpected orchestrator error ({type(exc).__name__}).",
                ),
            )
        if job.status is JobStatus.SUCCEEDED:
            for hook in self.post_success_hooks:
                try:
                    hook(job)
                except Exception:
                    logger.exception("post-success hook failed for job %s", job_id)
        # Report first: a terminal job.json then always has a report next to it.
        self.store.save_report(self._build_report(job, evidence, evaluations))
        self.store.save_job(job)
        return job

    def run_safely(self, job_id: str) -> None:
        """Background-task entry point: never raises."""
        try:
            self.run(job_id)
        except Exception:
            logger.exception("job %s could not be run", job_id)

    def _failed(self, job: ProtectionJob, exc: AegisError) -> ProtectionJob:
        now = self.clock()
        return _evolve(
            job,
            status=JobStatus.FAILED,
            error=exc.to_info().model_dump(),
            output_artifacts=[],
            updated_at=now,
            finished_at=now,
        )

    def _execute(
        self,
        job: ProtectionJob,
        evidence: list[EvidenceRecord],
        evaluations: list[AttackEvaluation],
    ) -> list[Artifact]:
        policy = job.policy
        # Re-validate: the configuration may have changed since submission.
        spec = self.validate_policy(policy)
        store = self.store
        input_path = store.artifact_path(job.input_artifact)
        evidence.append(
            self._evidence(
                job,
                EvidenceKind.ARTIFACT_HASH,
                f"Input {job.input_artifact.name} hashed at ingestion.",
                artifact_sha256=job.input_artifact.sha256,
                data={"role": "input", "size_bytes": job.input_artifact.size_bytes},
            )
        )
        if policy.task is TaskKind.ATTACK_LAB and policy.authorization is not None:
            evidence.append(
                self._evidence(
                    job,
                    EvidenceKind.AUTHORIZATION,
                    f"Attack-lab task authorized by {policy.authorization.authorized_by} "
                    f"({policy.authorization.reference}).",
                    data=policy.authorization.model_dump(mode="json"),
                )
            )

        output_dir = store.outputs_dir(job.job_id)
        request = AdapterRequest(
            job_id=job.job_id,
            task=policy.task,
            backend=policy.backend,
            policy_name=policy.name,
            input_path=str(input_path),
            input_sha256=job.input_artifact.sha256,
            output_dir=str(output_dir),
            options=policy.options,
            authorization=policy.authorization if policy.task is TaskKind.ATTACK_LAB else None,
        )
        request_path = store.adapter_dir(job.job_id) / "request.json"
        store.write_atomic(request_path, request.model_dump_json(indent=2).encode("utf-8"))

        timeout = policy.timeout_seconds or spec.timeout_seconds
        invocation = self.runner.invoke(
            spec, request_path, work_dir=store.work_dir(job.job_id), timeout_seconds=timeout
        )
        evidence.append(self._invocation_evidence(job, invocation, timeout))
        if invocation.error is not None:
            raise AegisError.from_info(invocation.error)
        result = invocation.result
        assert result is not None

        actual_sha, _ = sha256_file(input_path)
        if actual_sha != job.input_artifact.sha256:
            raise AegisError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                "The input artifact was modified while the adapter ran.",
                {"expected_sha256": job.input_artifact.sha256, "actual_sha256": actual_sha},
            )

        outputs: list[Artifact] = []
        by_path: dict[str, Artifact] = {}
        for item in result.outputs:
            artifact = store.register_file(
                job.job_id, output_dir / item.path, ArtifactRole.OUTPUT, within=output_dir
            )
            if artifact.storage_path in {a.storage_path for a in outputs}:
                raise AegisError(
                    ErrorCode.ADAPTER_INVALID_OUTPUT, f"Output {item.path!r} is listed twice."
                )
            outputs.append(artifact)
            by_path[item.path] = artifact
        if policy.task is TaskKind.PROTECT and not outputs:
            raise AegisError(
                ErrorCode.ADAPTER_INVALID_OUTPUT,
                "Adapter reported success but produced no output artifacts.",
            )

        new_evaluations: list[AttackEvaluation] = []
        for item in result.attack_evaluations:
            if item.target is None:
                target_sha = None
            elif item.target == "input":
                target_sha = job.input_artifact.sha256
            elif item.target in by_path:
                target_sha = by_path[item.target].sha256
            else:
                raise AegisError(
                    ErrorCode.ADAPTER_INVALID_OUTPUT,
                    f"Attack evaluation targets unknown artifact {item.target!r}.",
                )
            new_evaluations.append(
                AttackEvaluation(
                    evaluation_id=_new_id(),
                    job_id=job.job_id,
                    attack=item.attack,
                    outcome=item.outcome,
                    target_artifact_sha256=target_sha,
                    details=item.details,
                    metrics=item.metrics,
                    source=EvidenceSource.ADAPTER,
                    evaluated_at=self.clock(),
                )
            )
        if policy.task is TaskKind.ATTACK_LAB and not new_evaluations:
            raise AegisError(
                ErrorCode.ADAPTER_INVALID_OUTPUT,
                "Attack-lab adapter reported success but returned no attack evaluations.",
            )
        if policy.task is TaskKind.PROTECT and new_evaluations:
            raise AegisError(
                ErrorCode.ADAPTER_INVALID_OUTPUT,
                "Attack evaluations are only accepted for authorized attack-lab tasks.",
            )

        for artifact in outputs:
            evidence.append(
                self._evidence(
                    job,
                    EvidenceKind.ARTIFACT_HASH,
                    f"Output {artifact.name} hashed by the orchestrator.",
                    artifact_sha256=artifact.sha256,
                    data={"role": "output", "size_bytes": artifact.size_bytes},
                )
            )
        for item in result.evidence:
            evidence.append(
                self._evidence(
                    job,
                    EvidenceKind.ADAPTER_CLAIM,
                    item.summary,
                    source=EvidenceSource.ADAPTER,
                    data=item.data,
                )
            )
        evaluations.extend(new_evaluations)
        return outputs

    # --------------------------------------------------------------- evidence

    def _evidence(
        self,
        job: ProtectionJob,
        kind: EvidenceKind,
        summary: str,
        *,
        source: EvidenceSource = EvidenceSource.ORCHESTRATOR,
        artifact_sha256: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=_new_id(),
            job_id=job.job_id,
            kind=kind,
            source=source,
            summary=summary,
            artifact_sha256=artifact_sha256,
            data=data or {},
            created_at=self.clock(),
        )

    def _invocation_evidence(
        self, job: ProtectionJob, inv: AdapterInvocation, timeout: int
    ) -> EvidenceRecord:
        data: dict[str, Any] = {
            "argv": inv.argv,
            "exit_code": inv.exit_code,
            "timed_out": inv.timed_out,
            "timeout_seconds": timeout,
            "duration_seconds": inv.duration_seconds,
            "stdout_bytes": inv.stdout_bytes,
            "stdout_sha256": inv.stdout_sha256,
        }
        if inv.stderr:
            log_path = self.store.adapter_dir(job.job_id) / "stderr.log"
            self.store.write_atomic(log_path, inv.stderr)
            log = self.store.register_file(
                job.job_id, log_path, ArtifactRole.LOG, within=log_path.parent
            )
            data["stderr_log"] = log.storage_path
            data["stderr_sha256"] = log.sha256
        outcome = "timed out" if inv.timed_out else f"exited with {inv.exit_code}"
        if inv.exit_code is None and not inv.timed_out:
            outcome = "was not started"
        return self._evidence(
            job,
            EvidenceKind.ADAPTER_INVOCATION,
            f"Adapter for backend {job.policy.backend!r} {outcome}.",
            data=data,
        )

    # ----------------------------------------------------------------- report

    def _build_report(
        self,
        job: ProtectionJob,
        evidence: list[EvidenceRecord],
        evaluations: list[AttackEvaluation],
    ) -> ProtectionReport:
        return ProtectionReport(
            report_id=_new_id(),
            job_id=job.job_id,
            status=job.status,
            generated_at=self.clock(),
            policy=job.policy,
            input_artifact=job.input_artifact,
            output_artifacts=job.output_artifacts,
            evidence=evidence,
            attack_evaluations=evaluations,
            error=job.error,
            summary=_summarize(job, evaluations),
        )

    # ---------------------------------------------------------------- queries

    def get_job(self, job_id: str) -> ProtectionJob:
        return self.store.load_job(job_id)

    def get_report(self, job_id: str) -> ProtectionReport:
        job = self.store.load_job(job_id)
        if not job.status.is_terminal:
            raise AegisError(
                ErrorCode.REPORT_NOT_READY,
                f"Job {job_id} is {job.status.value}; its report is not available yet.",
                {"status": job.status.value},
            )
        report = self.store.load_report(job_id)
        if report is None:
            raise AegisError(ErrorCode.STORAGE_ERROR, f"Report for job {job_id} is missing.")
        return report

    def find_output(self, job_id: str, sha256: str) -> tuple[ProtectionJob, Artifact]:
        """The registered output with this digest of a succeeded job, or ARTIFACT_NOT_FOUND."""
        job = self.store.load_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            for artifact in job.output_artifacts:
                if artifact.sha256 == sha256:
                    return job, artifact
        raise AegisError(
            ErrorCode.ARTIFACT_NOT_FOUND,
            f"Job {job_id} has no output artifact with that SHA-256.",
            {"kind": "artifact", "job_status": job.status.value},
        )

    def read_output(self, job_id: str, sha256: str) -> tuple[ProtectionJob, Artifact, bytes]:
        """Bytes of a registered output, re-hashed against Core's record before return."""
        job, artifact = self.find_output(job_id, sha256)
        data = self.store.read_artifact_verified(artifact, max_bytes=MAX_OUTPUT_READ_BYTES)
        return job, artifact, data

    def list_jobs(self) -> list[ProtectionJob]:
        return [self.store.load_job(job_id) for job_id in self.store.list_job_ids()]


def _evolve(job: ProtectionJob, **updates: Any) -> ProtectionJob:
    """Copy a job with updates, re-running all validators."""
    data = job.model_dump()
    data.update(updates)
    return ProtectionJob.model_validate(data)


def _summarize(job: ProtectionJob, evaluations: list[AttackEvaluation]) -> str:
    backend, task = job.policy.backend, job.policy.task.value
    if job.status is JobStatus.FAILED:
        assert job.error is not None
        return (
            f"Job failed: backend {backend!r} did not complete task {task!r} "
            f"({job.error.code.value}: {job.error.message})"
        )
    text = (
        f"Backend {backend!r} completed task {task!r} and produced "
        f"{len(job.output_artifacts)} output artifact(s)."
    )
    if evaluations:
        counts = Counter(e.outcome.value for e in evaluations)
        breakdown = ", ".join(f"{n} {outcome}" for outcome, n in sorted(counts.items()))
        text += f" {len(evaluations)} attack evaluation(s): {breakdown}."
    return text
