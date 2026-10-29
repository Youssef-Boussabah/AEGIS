from aegis_provenance.watermark.benchmark import run_watermark_evaluation
from aegis_provenance.watermark.engine import (
    embed_binary_watermark,
    embed_text_ir_watermark,
    extract_binary_watermark,
    extract_text_ir_watermark,
)
from aegis_provenance.watermark.models import WatermarkPayload


def test_binary_watermark_roundtrip():
    payload = WatermarkPayload(
        owner_id="org-aegis",
        custom_tag="release-v1.0",
    )
    raw_data = b"\x7fELFbinary-code-here"
    marked = embed_binary_watermark(raw_data, payload)

    assert len(marked) > len(raw_data)
    res = extract_binary_watermark(marked)
    assert res.detected is True
    assert res.confidence == 1.0
    assert res.payload.owner_id == "org-aegis"
    assert res.payload.custom_tag == "release-v1.0"


def test_binary_watermark_unmarked_control():
    raw_data = b"\x7fELFplain-unmarked-code"
    res = extract_binary_watermark(raw_data)
    assert res.detected is False
    assert res.confidence == 0.0


def test_binary_watermark_tampered_checksum():
    payload = WatermarkPayload(owner_id="org-aegis")
    marked = bytearray(embed_binary_watermark(b"data", payload))

    # Corrupt payload bytes in the middle of the mark
    marked[-15] ^= 0xFF
    res = extract_binary_watermark(bytes(marked))
    assert res.detected is False


def test_text_ir_watermark_roundtrip():
    ir = "define i32 @test() {\n  ret i32 42\n}"
    payload = WatermarkPayload(owner_id="ir-owner", custom_tag="llvm-shield-v1")
    marked = embed_text_ir_watermark(ir, payload)

    assert "!aegis.watermark" in marked
    res = extract_text_ir_watermark(marked)
    assert res.detected is True
    assert res.confidence == 1.0
    assert res.payload.owner_id == "ir-owner"


def test_text_ir_watermark_unmarked_control():
    ir = "define i32 @test() {\n  ret i32 42\n}"
    res = extract_text_ir_watermark(ir)
    assert res.detected is False


def test_watermark_evaluation_metrics():
    metrics = run_watermark_evaluation()
    assert metrics.unmarked_fpr == 0.0
    assert metrics.marked_tpr == 1.0
    assert metrics.cross_mark_collisions == 0
    assert metrics.retention_under_formatting == 1.0
    assert len(metrics.limitations) > 0
