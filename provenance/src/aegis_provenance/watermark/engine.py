"""Watermark embedding and extraction engines for binary artifacts and LLVM IR text."""

from __future__ import annotations

import base64
import json
import re
import struct
import zlib
from pathlib import Path

from aegis_provenance.canonical import canonical_json
from aegis_provenance.watermark.models import (
    WatermarkDetectionResult,
    WatermarkPayload,
)

# Binary Watermark framing
BIN_MAGIC_START = b"\x1bAEGIS_WM\x01"
BIN_MAGIC_END = b"\x1bEND_WM\x1b"

# Text IR pattern
IR_WM_PATTERN = re.compile(
    r'!aegis\.watermark\s*=\s*!\{\s*!"AEGIS_WM_V1"\s*,\s*!"(?P<payload>[A-Za-z0-9+/=]+)"\s*,\s*!"(?P<crc>[0-9a-f]{8})"\s*\}'
)
IR_COMMENT_WM_PATTERN = re.compile(
    r';\s*aegis-watermark:\s*(?P<payload>[A-Za-z0-9+/=]+):(?P<crc>[0-9a-f]{8})'
)


def embed_binary_watermark(data: bytes, payload: WatermarkPayload) -> bytes:
    """Embed a framed, checksummed binary watermark into byte stream."""
    payload_bytes = canonical_json(payload)
    if len(payload_bytes) > 65535:
        raise ValueError("Watermark payload exceeds maximum 64KB capacity")

    length_header = struct.pack(">H", len(payload_bytes))
    framed_content = BIN_MAGIC_START + length_header + payload_bytes
    crc = struct.pack(">I", zlib.crc32(framed_content))
    watermark_block = framed_content + crc + BIN_MAGIC_END

    return data + watermark_block


def extract_binary_watermark(data: bytes) -> WatermarkDetectionResult:
    """Scan and extract binary watermark from byte stream."""
    idx = 0
    magic_len = len(BIN_MAGIC_START)
    while True:
        pos = data.find(BIN_MAGIC_START, idx)
        if pos == -1:
            break

        # Check minimum size: magic(10) + length(2) + crc(4) + end_magic(8) = 24
        if pos + magic_len + 2 + 4 + len(BIN_MAGIC_END) > len(data):
            idx = pos + 1
            continue

        length_bytes = data[pos + magic_len : pos + magic_len + 2]
        payload_len = struct.unpack(">H", length_bytes)[0]
        end_pos = pos + magic_len + 2 + payload_len

        if end_pos + 4 + len(BIN_MAGIC_END) > len(data):
            idx = pos + 1
            continue

        payload_bytes = data[pos + magic_len + 2 : end_pos]
        stored_crc = data[end_pos : end_pos + 4]
        footer = data[end_pos + 4 : end_pos + 4 + len(BIN_MAGIC_END)]

        if footer != BIN_MAGIC_END:
            idx = pos + 1
            continue

        # Verify CRC32
        framed_content = data[pos:end_pos]
        expected_crc = struct.pack(">I", zlib.crc32(framed_content))
        if stored_crc != expected_crc:
            idx = pos + 1
            continue

        # Parse JSON
        try:
            payload_dict = json.loads(payload_bytes.decode("utf-8"))
            parsed_payload = WatermarkPayload.model_validate(payload_dict)
            return WatermarkDetectionResult(
                detected=True,
                payload=parsed_payload,
                confidence=1.0,
                raw_payload_bytes=payload_bytes.hex(),
                extraction_notes="Valid binary watermark extracted with matching CRC32 checksum.",
            )
        except Exception as exc:
            return WatermarkDetectionResult(
                detected=False,
                confidence=0.5,
                extraction_notes=f"Found watermark frame but payload parsing failed: {exc}",
            )

    return WatermarkDetectionResult(
        detected=False,
        confidence=0.0,
        extraction_notes="No valid watermark block found in byte stream.",
    )


def embed_text_ir_watermark(ir_text: str, payload: WatermarkPayload) -> str:
    """Embed structured watermark metadata into textual LLVM IR."""
    canon = canonical_json(payload)
    b64 = base64.b64encode(canon).decode("ascii")
    crc_hex = f"{zlib.crc32(canon) & 0xFFFFFFFF:08x}"

    meta_line = '!aegis.watermark = !{!"AEGIS_WM_V1", !"' + b64 + '", !"' + crc_hex + '"}'
    comment_line = f"; aegis-watermark: {b64}:{crc_hex}"

    lines = ir_text.rstrip().splitlines()
    # Insert comment at top and metadata node at bottom
    result = [comment_line] + lines + ["", meta_line, ""]
    return "\n".join(result)


def extract_text_ir_watermark(ir_text: str) -> WatermarkDetectionResult:
    """Extract watermark from LLVM IR metadata node or comment."""
    match = IR_WM_PATTERN.search(ir_text) or IR_COMMENT_WM_PATTERN.search(ir_text)
    if not match:
        return WatermarkDetectionResult(
            detected=False,
            confidence=0.0,
            extraction_notes="No watermark pattern found in LLVM IR text.",
        )

    b64_payload = match.group("payload")
    stored_crc_hex = match.group("crc")

    try:
        raw_bytes = base64.b64decode(b64_payload, validate=True)
    except Exception as exc:
        return WatermarkDetectionResult(
            detected=False,
            confidence=0.2,
            extraction_notes=f"Invalid base64 payload: {exc}",
        )

    expected_crc_hex = f"{zlib.crc32(raw_bytes) & 0xFFFFFFFF:08x}"
    if stored_crc_hex.lower() != expected_crc_hex.lower():
        return WatermarkDetectionResult(
            detected=False,
            confidence=0.4,
            extraction_notes="Watermark CRC32 mismatch; possible tampering or corruption.",
        )

    try:
        payload_dict = json.loads(raw_bytes.decode("utf-8"))
        parsed = WatermarkPayload.model_validate(payload_dict)
        return WatermarkDetectionResult(
            detected=True,
            payload=parsed,
            confidence=1.0,
            raw_payload_bytes=raw_bytes.hex(),
            extraction_notes="Valid LLVM IR watermark extracted with matching CRC32.",
        )
    except Exception as exc:
        return WatermarkDetectionResult(
            detected=False,
            confidence=0.5,
            extraction_notes=f"Watermark payload schema validation failed: {exc}",
        )
