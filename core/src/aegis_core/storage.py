"""Local filesystem artifact store.

Layout under the store root::

    jobs/<job_id>/job.json          current ProtectionJob
    jobs/<job_id>/report.json       ProtectionReport (written once the job is terminal)
    jobs/<job_id>/inputs/<name>     ingested input artifact
    jobs/<job_id>/outputs/          adapter output directory
    jobs/<job_id>/adapter/          adapter request and captured logs
    jobs/<job_id>/work/             adapter working directory
    jobs/<job_id>/attestation/      optional (0700): attestation.json, signed
                                    manifests and Sentinel policies per output,
                                    written by aegis_provenance.jobs

All JSON writes are atomic (write to a temp file, then rename).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import uuid
from pathlib import Path

from pydantic import BaseModel, ValidationError

from .errors import AegisError
from .models import (
    ID_PATTERN,
    Artifact,
    ArtifactRole,
    ErrorCode,
    ProtectionJob,
    ProtectionReport,
    utcnow,
)

_CHUNK = 1024 * 1024
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def safe_artifact_name(name: str, fallback: str = "artifact.bin") -> str:
    """Reduce an untrusted file name to a safe single path component."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE_NAME_CHARS.sub("_", base).lstrip("._-")
    base = base[:128]
    return base or fallback


def validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not re.match(ID_PATTERN, job_id):
        raise AegisError(ErrorCode.JOB_NOT_FOUND, "Job id must be 32 lowercase hex characters.")
    return job_id


class LocalArtifactStore:
    def __init__(self, root: Path, *, max_input_bytes: int):
        self.root = Path(root).resolve()
        self.max_input_bytes = max_input_bytes

    # ---------------------------------------------------------------- layout

    @property
    def jobs_root(self) -> Path:
        return self.root / "jobs"

    def initialize(self) -> None:
        try:
            self.jobs_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AegisError(
                ErrorCode.STORAGE_ERROR, f"Cannot create artifact store: {exc.strerror}"
            ) from None

    def is_writable(self) -> bool:
        try:
            self.initialize()
            with tempfile.NamedTemporaryFile(dir=self.jobs_root, prefix=".probe-"):
                pass
            return True
        except (AegisError, OSError):
            return False

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_root / validate_job_id(job_id)

    def inputs_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "inputs"

    def outputs_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "outputs"

    def adapter_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "adapter"

    def work_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "work"

    def attestation_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "attestation"

    def ensure_attestation_dir(self, job_id: str) -> Path:
        path = self.attestation_dir(job_id)
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise AegisError(ErrorCode.STORAGE_ERROR, "Attestation directory is not a directory.")
        return path

    def create_job_dir(self, job_id: str) -> Path:
        self.initialize()
        job_dir = self.job_dir(job_id)
        job_dir.mkdir()
        for sub in ("inputs", "outputs", "adapter", "work"):
            (job_dir / sub).mkdir()
        return job_dir

    def remove_job_dir(self, job_id: str) -> None:
        shutil.rmtree(self.job_dir(job_id), ignore_errors=True)

    def resolve_storage_path(self, storage_path: str) -> Path:
        path = (self.root / storage_path).resolve()
        if not path.is_relative_to(self.root):
            raise AegisError(ErrorCode.STORAGE_ERROR, "Artifact path escapes the store root.")
        return path

    def artifact_path(self, artifact: Artifact) -> Path:
        return self.resolve_storage_path(artifact.storage_path)

    # -------------------------------------------------------------- artifacts

    def ingest_input(
        self,
        job_id: str,
        name: str,
        *,
        source: Path | None = None,
        data: bytes | None = None,
    ) -> Artifact:
        if (source is None) == (data is None):
            raise ValueError("pass exactly one of source or data")
        safe_name = safe_artifact_name(name, fallback="input.bin")
        dest = self.inputs_dir(job_id) / safe_name
        digest = hashlib.sha256()
        size = 0
        try:
            if data is not None:
                if len(data) > self.max_input_bytes:
                    raise self._too_large(len(data))
                digest.update(data)
                size = len(data)
                dest.write_bytes(data)
            else:
                assert source is not None
                if not source.is_file():
                    raise AegisError(
                        ErrorCode.INPUT_NOT_FOUND,
                        f"Input {source} does not exist or is not a regular file.",
                    )
                with open(source, "rb") as src, open(dest, "xb") as out:
                    while chunk := src.read(_CHUNK):
                        size += len(chunk)
                        if size > self.max_input_bytes:
                            raise self._too_large(size)
                        digest.update(chunk)
                        out.write(chunk)
        except AegisError:
            dest.unlink(missing_ok=True)
            raise
        except OSError as exc:
            dest.unlink(missing_ok=True)
            raise AegisError(
                ErrorCode.STORAGE_ERROR, f"Failed to store input: {exc.strerror}"
            ) from None
        return Artifact(
            artifact_id=uuid.uuid4().hex,
            name=safe_name,
            role=ArtifactRole.INPUT,
            sha256=digest.hexdigest(),
            size_bytes=size,
            storage_path=dest.relative_to(self.root).as_posix(),
            created_at=utcnow(),
        )

    def _too_large(self, size: int) -> AegisError:
        return AegisError(
            ErrorCode.INPUT_TOO_LARGE,
            f"Input exceeds the configured limit of {self.max_input_bytes} bytes.",
            {"max_input_bytes": self.max_input_bytes, "observed_bytes_at_least": size},
        )

    def register_file(
        self, job_id: str, path: Path, role: ArtifactRole, *, within: Path
    ) -> Artifact:
        """Hash a file that already lives inside `within` (a job sub-directory)."""
        within = within.resolve()
        if not within.is_relative_to(self.job_dir(job_id).resolve()):
            raise AegisError(ErrorCode.STORAGE_ERROR, "Registration root is outside the job.")
        if path.is_symlink():
            raise AegisError(
                ErrorCode.ADAPTER_INVALID_OUTPUT, f"Artifact {path.name!r} is a symlink."
            )
        resolved = path.resolve()
        if not resolved.is_relative_to(within):
            raise AegisError(
                ErrorCode.ADAPTER_INVALID_OUTPUT,
                "Artifact path escapes its directory.",
                {"path": str(path)},
            )
        if not resolved.is_file():
            raise AegisError(
                ErrorCode.ADAPTER_INVALID_OUTPUT,
                f"Artifact {resolved.relative_to(within).as_posix()!r} does not exist "
                "or is not a regular file.",
            )
        sha, size = sha256_file(resolved)
        return Artifact(
            artifact_id=uuid.uuid4().hex,
            name=safe_artifact_name(resolved.name),
            role=role,
            sha256=sha,
            size_bytes=size,
            storage_path=resolved.relative_to(self.root).as_posix(),
            created_at=utcnow(),
        )

    def read_bounded(self, path: Path, *, max_bytes: int) -> bytes:
        """Read a regular, non-symlink file inside the store, at most `max_bytes`.

        Raises FileNotFoundError when absent and AegisError(STORAGE_ERROR) when the
        path escapes the store, is not a regular file or is too large.
        """
        resolved_parent = path.parent.resolve()
        if not resolved_parent.is_relative_to(self.root):
            raise AegisError(ErrorCode.STORAGE_ERROR, "Path escapes the store root.")
        fd = os.open(resolved_parent / path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise AegisError(ErrorCode.STORAGE_ERROR, f"{path.name!r} is not a regular file.")
            if info.st_size > max_bytes:
                raise AegisError(
                    ErrorCode.STORAGE_ERROR,
                    f"{path.name!r} exceeds the {max_bytes}-byte read limit.",
                    {"size_bytes": info.st_size, "max_bytes": max_bytes},
                )
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(fd, _CHUNK):
                total += len(chunk)
                if total > max_bytes:
                    raise AegisError(
                        ErrorCode.STORAGE_ERROR, f"{path.name!r} grew past the read limit."
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def read_artifact_verified(self, artifact: Artifact, *, max_bytes: int) -> bytes:
        """Return an artifact's bytes only if they still hash to the recorded SHA-256.

        The bytes are read once, then hashed; callers serve exactly the bytes that
        were checked. A symlink, missing file or changed content fails explicitly.
        """
        try:
            # Unresolved path: read_bounded refuses a symlink as the final component.
            data = self.read_bounded(self.root / artifact.storage_path, max_bytes=max_bytes)
        except FileNotFoundError:
            raise AegisError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Stored artifact {artifact.name!r} is missing.",
                {"expected_sha256": artifact.sha256},
            ) from None
        except OSError as exc:
            raise AegisError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Stored artifact {artifact.name!r} cannot be read safely ({exc.strerror}).",
                {"expected_sha256": artifact.sha256},
            ) from None
        actual = hashlib.sha256(data).hexdigest()
        if actual != artifact.sha256 or len(data) != artifact.size_bytes:
            raise AegisError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Stored artifact {artifact.name!r} no longer matches its recorded SHA-256.",
                {"expected_sha256": artifact.sha256, "actual_sha256": actual},
            )
        return data

    # ------------------------------------------------------------------- json

    def write_atomic(self, path: Path, content: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _write_model(self, path: Path, model: BaseModel) -> None:
        self.write_atomic(path, model.model_dump_json(indent=2).encode("utf-8"))

    def save_job(self, job: ProtectionJob) -> None:
        self._write_model(self.job_dir(job.job_id) / "job.json", job)

    def load_job(self, job_id: str) -> ProtectionJob:
        path = self.job_dir(job_id) / "job.json"
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            raise AegisError(
                ErrorCode.JOB_NOT_FOUND, f"Job {job_id} was not found.", {"job_id": job_id}
            ) from None
        try:
            return ProtectionJob.model_validate_json(raw)
        except ValidationError:
            raise AegisError(
                ErrorCode.STORAGE_ERROR, f"Stored record for job {job_id} is corrupt."
            ) from None

    def list_job_ids(self) -> list[str]:
        if not self.jobs_root.is_dir():
            return []
        return sorted(
            p.name
            for p in self.jobs_root.iterdir()
            if re.match(ID_PATTERN, p.name) and (p / "job.json").is_file()
        )

    def save_report(self, report: ProtectionReport) -> None:
        self._write_model(self.job_dir(report.job_id) / "report.json", report)

    def load_report(self, job_id: str) -> ProtectionReport | None:
        path = self.job_dir(job_id) / "report.json"
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            return ProtectionReport.model_validate_json(raw)
        except ValidationError:
            raise AegisError(
                ErrorCode.STORAGE_ERROR, f"Stored report for job {job_id} is corrupt."
            ) from None

    def claim_job(self, job_id: str) -> bool:
        """Atomically mark a job as claimed for execution (works across processes)."""
        try:
            fd = os.open(self.job_dir(job_id) / ".claimed", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        os.close(fd)
        return True
