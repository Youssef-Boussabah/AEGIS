"""Per-grant usage ledger for candidate execution (``aegis.core.grant-ledger.v1``).

Budgets in a ``CandidateExecutionGrant`` (compilations and executions per
candidate, total wall-clock reservation) apply to the **grant**, across every
session and every process that uses it. Opening another session, or restarting
the process, therefore never resets them.

Layout under the store root::

    lab-grants/<grant_id>/ledger.json   usage so far (atomic replace, fsync)
    lab-grants/<grant_id>/ledger.lock   exclusive flock held for each read-modify-write

A grant id is bound to the first grant digest that used it. A different grant
with the same id is refused (``grant_ledger_conflict``), so editing a grant while
keeping its id cannot reset its usage. An unreadable or invalid ledger fails
closed with ``STORAGE_ERROR``. The ledger trusts the local filesystem: anyone who
can delete the operator's store can reset it, as they could change the config.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictInt, ValidationError

from .config import AegisConfig
from .errors import AegisError
from .lab_authorization import CandidateExecutionGrant, ExecutionStage, refuse
from .models import ID_PATTERN, AegisModel, ErrorCode, ObjectId, Sha256

try:  # POSIX only; candidate execution is refused where it is unavailable.
    import fcntl
except ImportError:  # pragma: no cover - not reachable on Linux
    fcntl = None  # type: ignore[assignment]

LEDGER_SCHEMA = "aegis.core.grant-ledger.v1"
LEDGER_DIR = "lab-grants"
MAX_LEDGER_BYTES = 256 * 1024

Count = Annotated[StrictInt, Field(ge=0)]


class GrantUsage(AegisModel):
    """Usage of one grant, summed over all of its sessions."""

    schema_version: Literal["aegis.core.grant-ledger.v1"] = LEDGER_SCHEMA
    grant_id: ObjectId
    grant_sha256: Sha256
    sessions_opened: Count = 0
    compilations: dict[ObjectId, Count] = Field(default_factory=dict)
    executions: dict[ObjectId, Count] = Field(default_factory=dict)
    wall_ms_reserved: Count = 0
    updated_at: AwareDatetime


def _storage_error(message: str) -> AegisError:
    return AegisError(ErrorCode.STORAGE_ERROR, message)


class GrantLedger:
    """File-backed ledger. Each update holds an exclusive lock on the grant's lock file."""

    def __init__(self, root: Path):
        self.root = Path(root)

    @classmethod
    def for_config(cls, config: AegisConfig) -> GrantLedger:
        return cls(Path(config.storage.root) / LEDGER_DIR)

    # ----------------------------------------------------------------- public

    def usage(self, grant_id: str) -> GrantUsage | None:
        """Current usage, or None when the grant has never been used."""
        with self._locked(grant_id) as directory:
            return self._read(directory)

    def register_session(
        self, grant: CandidateExecutionGrant, digest: str, now: datetime
    ) -> GrantUsage:
        """Bind the grant id to its digest (first use) and count the session."""
        with self._locked(grant.grant_id) as directory:
            usage = self._current(directory, grant, digest, now)
            usage.sessions_opened += 1
            return self._write(directory, usage, now)

    def reserve(
        self,
        grant: CandidateExecutionGrant,
        digest: str,
        *,
        stage: ExecutionStage,
        candidate_id: str,
        wall_ms: int,
        now: datetime,
    ) -> GrantUsage:
        """Check the grant-wide budgets and reserve one run. Raise without changing anything."""
        with self._locked(grant.grant_id) as directory:
            usage = self._current(directory, grant, digest, now)
            if stage == "compile":
                if usage.compilations.get(candidate_id, 0) >= grant.max_compilations_per_candidate:
                    raise refuse(
                        "compilation_budget_exhausted",
                        "The grant's compilation budget for this candidate is used up.",
                    )
            elif usage.executions.get(candidate_id, 0) >= grant.max_executions_per_candidate:
                raise refuse(
                    "execution_budget_exhausted",
                    "The grant's execution budget for this candidate is used up.",
                )
            if usage.wall_ms_reserved + wall_ms > grant.max_total_wall_ms:
                raise refuse(
                    "wall_budget_exhausted",
                    "The grant's total wall-clock budget would be exceeded.",
                    reserved_ms=usage.wall_ms_reserved,
                    requested_ms=wall_ms,
                    budget_ms=grant.max_total_wall_ms,
                )
            # Reserved before the run and never returned: a failed or killed run
            # still consumes its budget.
            counter = usage.compilations if stage == "compile" else usage.executions
            counter[candidate_id] = counter.get(candidate_id, 0) + 1
            usage.wall_ms_reserved += wall_ms
            return self._write(directory, usage, now)

    # ---------------------------------------------------------------- helpers

    def _current(
        self, directory: Path, grant: CandidateExecutionGrant, digest: str, now: datetime
    ) -> GrantUsage:
        usage = self._read(directory)
        if usage is None:
            return GrantUsage(grant_id=grant.grant_id, grant_sha256=digest, updated_at=now)
        if usage.grant_id != grant.grant_id:
            raise _storage_error("The grant ledger belongs to another grant id.")
        if usage.grant_sha256 != digest:
            raise refuse(
                "grant_ledger_conflict",
                "This grant id was already used by a grant with different contents.",
                recorded_grant_sha256=usage.grant_sha256,
                grant_sha256=digest,
            )
        return usage

    @contextlib.contextmanager
    def _locked(self, grant_id: str) -> Iterator[Path]:
        if not isinstance(grant_id, str) or not re.fullmatch(ID_PATTERN, grant_id):
            raise _storage_error("Invalid grant id for the ledger.")
        if fcntl is None:  # pragma: no cover
            raise _storage_error("The grant ledger needs POSIX file locks.")
        directory = self.root / grant_id
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            _reject_symlink(self.root)
            directory.mkdir(mode=0o700, exist_ok=True)
            _reject_symlink(directory)
            fd = os.open(
                directory / "ledger.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except AegisError:
            raise
        except OSError:
            raise _storage_error("The grant ledger directory cannot be used.") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield directory
        finally:
            os.close(fd)  # closing the descriptor releases the lock

    def _read(self, directory: Path) -> GrantUsage | None:
        path = directory / "ledger.json"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError:
            raise _storage_error("The grant ledger cannot be opened.") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LEDGER_BYTES:
                raise _storage_error("The grant ledger is not a bounded regular file.")
            data = os.read(fd, MAX_LEDGER_BYTES + 1)
        except OSError:
            raise _storage_error("The grant ledger cannot be read.") from None
        finally:
            os.close(fd)
        try:
            return GrantUsage.model_validate_json(data, strict=True)
        except ValidationError:
            # Unknown usage must never be treated as zero usage.
            raise _storage_error("The grant ledger is corrupt; refusing to continue.") from None

    def _write(self, directory: Path, usage: GrantUsage, now: datetime) -> GrantUsage:
        usage.updated_at = now
        usage = GrantUsage.model_validate(usage.model_dump())
        data = usage.model_dump_json(indent=2).encode("utf-8")
        if len(data) > MAX_LEDGER_BYTES:
            raise _storage_error("The grant ledger would exceed its size limit.")
        tmp = directory / f".ledger.{os.getpid()}.tmp"
        try:
            fd = os.open(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, directory / "ledger.json")
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise _storage_error("The grant ledger cannot be written.") from None
        return usage


def _reject_symlink(path: Path) -> None:
    if stat.S_ISLNK(os.lstat(path).st_mode):
        raise _storage_error("The grant ledger path must not be a symlink.")
