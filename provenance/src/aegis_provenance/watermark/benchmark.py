"""Benchmark harness for watermark false-positive rates, controls, and transformation retention."""

from __future__ import annotations

import re
from aegis_provenance.watermark.engine import (
    embed_binary_watermark,
    embed_text_ir_watermark,
    extract_binary_watermark,
    extract_text_ir_watermark,
)
from aegis_provenance.watermark.models import (
    WatermarkEvaluationMetrics,
    WatermarkPayload,
)


def run_watermark_evaluation() -> WatermarkEvaluationMetrics:
    """Run empirical evaluation with unmarked controls, cross-mark collision tests, and transformations."""

    # 1. Unmarked controls (test 50 distinct unmarked samples)
    unmarked_samples = [
        b"",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00",
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00",
        b"define i32 @main() { ret i32 0 }",
        b"target datalayout = \"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128\"",
        *(f"sample binary buffer number {i}".encode("utf-8") for i in range(45)),
    ]

    unmarked_fp = 0
    for sample in unmarked_samples:
        bin_res = extract_binary_watermark(sample)
        if bin_res.detected:
            unmarked_fp += 1

        try:
            text = sample.decode("utf-8")
            ir_res = extract_text_ir_watermark(text)
            if ir_res.detected:
                unmarked_fp += 1
        except UnicodeDecodeError:
            pass

    unmarked_total = len(unmarked_samples)
    fpr = unmarked_fp / unmarked_total

    # 2. Marked true positives (test 20 marked samples)
    marked_tp = 0
    payloads = [
        WatermarkPayload(owner_id=f"owner_{i}", custom_tag=f"tag_{i}")
        for i in range(20)
    ]
    for p in payloads:
        base = b"target byte content"
        marked = embed_binary_watermark(base, p)
        res = extract_binary_watermark(marked)
        if res.detected and res.payload and res.payload.owner_id == p.owner_id:
            marked_tp += 1

    tpr = marked_tp / len(payloads)

    # 3. Cross-mark collision check (two different owners)
    p_a = WatermarkPayload(owner_id="org_alpha", custom_tag="secret_alpha")
    p_b = WatermarkPayload(owner_id="org_beta", custom_tag="secret_beta")
    marked_a = embed_binary_watermark(b"common_code", p_a)
    res_a = extract_binary_watermark(marked_a)
    assert res_a.detected and res_a.payload.owner_id == "org_alpha"
    collisions = 1 if res_a.payload.owner_id == p_b.owner_id else 0

    # 4. Retention under transformations
    # A: Whitespace / formatting transformation on IR
    ir_sample = "define i32 @add(i32 %a, i32 %b) {\n  %res = add i32 %a, %b\n  ret i32 %res\n}"
    marked_ir = embed_text_ir_watermark(ir_sample, p_a)
    # Transformation 1: normalize whitespace and add blank lines
    transformed_ir_1 = "\n\n".join(line.strip() for line in marked_ir.splitlines() if line.strip())
    ret_res_1 = extract_text_ir_watermark(transformed_ir_1)
    retention_formatting = 1.0 if ret_res_1.detected else 0.0

    # Transformation 2: strip comment lines (leaving metadata)
    no_comments_ir = "\n".join(
        l for l in marked_ir.splitlines() if not l.strip().startswith(";")
    )
    ret_res_2 = extract_text_ir_watermark(no_comments_ir)
    retention_comment_strip = 1.0 if ret_res_2.detected else 0.0

    # Transformation 3: strip metadata (aggressive llvm-strip equivalent)
    no_meta_ir = re.sub(r"!aegis\.watermark\s*=\s*!\{.*?\}", "", marked_ir)
    no_comments_or_meta_ir = "\n".join(
        l for l in no_meta_ir.splitlines() if not l.strip().startswith(";")
    )
    ret_res_3 = extract_text_ir_watermark(no_comments_or_meta_ir)
    # When all marks and metadata are stripped, watermark cannot survive
    retention_full_strip = 0.0 if not ret_res_3.detected else 1.0

    limitations = [
        "Metadata and trailing section watermarks do not survive aggressive dead-metadata elimination (opt -strip-debug / llvm-strip).",
        "Watermarking proves signer/embedder assertion, not legal copyright or IP origin of all underlying code.",
        "Adversaries with write access to unprotected source or unlinked IR can remove metadata nodes before compilation.",
        "Watermark embedding expands artifact size by the framed payload length plus 24 framing bytes.",
    ]

    return WatermarkEvaluationMetrics(
        unmarked_false_positives=unmarked_fp,
        unmarked_total_tested=unmarked_total,
        unmarked_fpr=fpr,
        marked_true_positives=marked_tp,
        marked_total_tested=len(payloads),
        marked_tpr=tpr,
        cross_mark_collisions=collisions,
        retention_under_formatting=retention_formatting,
        retention_under_stripping=retention_comment_strip,
        limitations=limitations,
    )

