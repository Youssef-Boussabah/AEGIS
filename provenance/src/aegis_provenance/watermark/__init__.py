"""AEGIS Watermark research, embedder, detector, and controls."""

from aegis_provenance.watermark.engine import (
    embed_binary_watermark,
    extract_binary_watermark,
    embed_text_ir_watermark,
    extract_text_ir_watermark,
)
from aegis_provenance.watermark.models import WatermarkDetectionResult, WatermarkPayload

__all__ = [
    "embed_binary_watermark",
    "extract_binary_watermark",
    "embed_text_ir_watermark",
    "extract_text_ir_watermark",
    "WatermarkDetectionResult",
    "WatermarkPayload",
]

