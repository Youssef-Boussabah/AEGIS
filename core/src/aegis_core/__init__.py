"""AEGIS core: contracts, local artifact storage and the protection orchestrator."""

__version__ = "0.1.0"

from .config import AdapterSpec, AegisConfig, load_config, resolve_config_path  # noqa: E402
from .errors import AegisError  # noqa: E402
from .models import (  # noqa: E402
    Artifact,
    ArtifactRole,
    AttackEvaluation,
    AttackLabAuthorization,
    AttackOutcome,
    ErrorCode,
    ErrorInfo,
    EvidenceKind,
    EvidenceRecord,
    EvidenceSource,
    JobStatus,
    ProtectionJob,
    ProtectionPolicy,
    ProtectionReport,
    TaskKind,
)
from .orchestrator import Orchestrator  # noqa: E402

__all__ = [
    "__version__",
    "AdapterSpec",
    "AegisConfig",
    "AegisError",
    "Artifact",
    "ArtifactRole",
    "AttackEvaluation",
    "AttackLabAuthorization",
    "AttackOutcome",
    "ErrorCode",
    "ErrorInfo",
    "EvidenceKind",
    "EvidenceRecord",
    "EvidenceSource",
    "JobStatus",
    "Orchestrator",
    "ProtectionJob",
    "ProtectionPolicy",
    "ProtectionReport",
    "TaskKind",
    "load_config",
    "resolve_config_path",
]
