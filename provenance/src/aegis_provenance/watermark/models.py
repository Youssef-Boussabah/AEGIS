"""Data models for watermarking research and detection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

WATERMARK_SCHEMA_VERSION: Literal["1"] = "1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WatermarkModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WatermarkPayload(WatermarkModel):
    schema_version: Literal["1"] = WATERMARK_SCHEMA_VERSION
    owner_id: str = Field(min_length=1, max_length=128)
    artifact_linkage: Sha256 | None = None
    created_at: AwareDatetime = Field(default_factory=utcnow)
    custom_tag: str | None = Field(default=None, max_length=256)


class WatermarkDetectionResult(WatermarkModel):
    detected: bool
    payload: WatermarkPayload | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    raw_payload_bytes: str | None = None
    extraction_notes: str | None = None


class WatermarkEvaluationMetrics(WatermarkModel):
    unmarked_false_positives: int
    unmarked_total_tested: int
    unmarked_fpr: float
    marked_true_positives: int
    marked_total_tested: int
    marked_tpr: float
    cross_mark_collisions: int
    retention_under_formatting: float
    retention_under_stripping: float
    limitations: list[str]

