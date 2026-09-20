"""judge tests — prompt template + bias controls + audit log + bias detector.

These are pure-Python unit tests (no LLM calls). The orchestrator's
LiteLLM-invoking path is covered by integration tests under
tests/test_judge_integration.py (gated by the @pytest.mark.live marker).
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from common.schema import JudgeLabel, Severity
from judge.prompt_template import (
    PREAMBLE,
    build_input_block,
    build_prompt,
    build_messages,
    parse_response,
    make_provider_tag,
)
from judge.bias_controls import (
    apply_position,
    apply_verbosity,
    apply_self_enhancement,
    verify_no_leakage,
)
from judge.audit_log import (
    AuditLog,
    AuditRecord,
    make_audit_record,
    verify_no_leakage as audit_verify_no_leakage,
)
from judge.bias_detector import (
    BiasTestResult,
    BiasSummary,
    run_position_test,
    run_verbosity_test,
    run_self_enhancement_test,
    run_full_protocol,
)


# ---------------------------------------------------------------------------
# Prompt template tests
# ---------------------------------------------------------------------------


class TestPromptTemplate:
    def test_preamble_is_nonempty(self):
        assert len(PREAMBLE.strip()) > 100
        assert "security code reviewer" in PREAMBLE.lower()

    def test_build_input_block(self):
        block = build_input_block(
            "x = 1",
            [{"tool": "bandit", "rule_id": "B101", "line": 1, "message": "x"}],
            "abc123",
        )
        assert "x = 1" in block
        assert "abc123" in block
        assert "B101" in block

    def test_build_messages_has_system_and_user(self):
        msgs = build_messages("x", [], "tag")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"

    def test_parse_response_clean_json(self):
        text = '{"verdict":"defect","cwe":"CWE-89","severity":"high","confidence":0.9,"evidence":"SQL injection"}'
        parsed = parse_response(text)
        assert parsed["verdict"] == "defect"
        assert parsed["cwe"] == "CWE-89"
        assert parsed["severity"] == "high"
        assert parsed["confidence"] == 0.9

    def test_parse_response_markdown_fenced(self):
        text = "```json\n{\"verdict\":\"no-defect\",\"cwe\":null,\"severity\":null,\"confidence\":0.5,\"evidence\":\"clean\"}\n```"
        parsed = parse_response(text)
        assert parsed["verdict"] == "no-defect"

    def test_parse_response_with_prose(self):
        text = 'Here is my verdict:\n{"verdict":"defect","cwe":"CWE-89","severity":"high","confidence":0.8,"evidence":"SQL injection on line 3"}\nThat is all.'
        parsed = parse_response(text)
        assert parsed["verdict"] == "defect"

    def test_parse_response_garbage_returns_inconclusive(self):
        parsed = parse_response("not json at all")
        assert parsed["verdict"] == "inconclusive"

    def test_parse_response_normalises_label(self):
        parsed = parse_response('{"verdict":"no_defect","cwe":null,"severity":null,"confidence":0.0,"evidence":"x"}')
        assert parsed["verdict"] == "no-defect"

    def test_parse_response_rejects_unknown_cwe(self):
        parsed = parse_response('{"verdict":"defect","cwe":"not-a-cwe","severity":"high","confidence":0.5,"evidence":"x"}')
        assert parsed["cwe"] is None

    def test_parse_response_clamps_confidence(self):
        parsed = parse_response('{"verdict":"defect","cwe":"CWE-89","severity":"high","confidence":1.5,"evidence":"x"}')
        assert parsed["confidence"] == 1.0
        parsed = parse_response('{"verdict":"defect","cwe":"CWE-89","severity":"high","confidence":-0.5,"evidence":"x"}')
        assert parsed["confidence"] == 0.0

    def test_make_provider_tag_is_deterministic(self):
        a = make_provider_tag("qwen2.5-coder:32b")
        b = make_provider_tag("qwen2.5-coder:32b")
        assert a == b
        assert len(a) == 8
        c = make_provider_tag("claude-3-5-sonnet")
        assert a != c


# ---------------------------------------------------------------------------
# Bias controls tests
# ---------------------------------------------------------------------------


class TestBiasControls:
    def test_apply_position_shuffles(self):
        candidates = [{"i": i} for i in range(10)]
        shuffled, key1 = apply_position(candidates, "freeze", "p1")
        assert shuffled != candidates or len(candidates) < 2
        # Reproducible: same key reproduces same shuffle
        shuffled2, _ = apply_position(candidates, "freeze", "p1", ordering_key=key1)
        assert shuffled == shuffled2

    def test_apply_position_different_prompts_get_different_keys(self):
        candidates = [{"i": i} for i in range(10)]
        _, key1 = apply_position(candidates, "freeze", "p1")
        _, key2 = apply_position(candidates, "freeze", "p2")
        assert key1 != key2

    def test_apply_verbosity_enforces_max_tokens(self):
        params = apply_verbosity({"temperature": 0.0})
        assert params["max_tokens"] == 224
        assert params["temperature"] == 0.0

    def test_apply_verbosity_does_not_mutate_input(self):
        original = {"temperature": 0.0}
        apply_verbosity(original)
        assert "max_tokens" not in original

    def test_apply_self_enhancement_returns_leakage_strings(self):
        _, leakage = apply_self_enhancement("abc123", "qwen2.5-coder:32b", "")
        assert "qwen2.5-coder:32b" in leakage

    def test_verify_no_leakage_pass(self):
        violations = verify_no_leakage("This prompt has nothing", ["secret"])
        assert violations == []

    def test_verify_no_leakage_detects(self):
        violations = verify_no_leakage("This prompt mentions secret", ["secret"])
        assert violations == ["secret"]


# ---------------------------------------------------------------------------
# Audit log tests
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_append_only_writes_jsonl(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path)
        log.write(AuditRecord(
            timestamp="2026-09-20T00:00:00Z",
            caller="test",
            prompt_id="p001",
            freeze_tag="vce-2026-09-20-frozen",
            provider="ollama",
            model_id="qwen2.5-coder:32b",
            seed=None,
            ordering_key=42,
            response='{"verdict":"defect"}',
            latency_ms=1200,
            leakage_check_passed=True,
        ))
        log.close()
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["prompt_id"] == "p001"
        assert rec["ordering_key"] == 42

    def test_make_audit_record_with_leakage(self):
        t0 = 1000.0
        record = make_audit_record(
            caller="orchestrator",
            prompt_id="p1",
            freeze_tag="vce-2026-09-20-frozen",
            provider="ollama",
            model_id="qwen2.5-coder:32b",
            seed=None,
            ordering_key=42,
            response="{}",
            prompt_text="This prompt mentions qwen2.5-coder:32b explicitly",
            leakage_strings=["qwen2.5-coder:32b"],
            start_time=t0,
        )
        assert not record.leakage_check_passed
        assert "qwen2.5-coder:32b" in record.leakage_violations


# ---------------------------------------------------------------------------
# Bias detector tests
# ---------------------------------------------------------------------------


class TestBiasDetector:
    def test_run_position_test_empty(self):
        result = run_position_test([])
        assert result.subsample_size == 0
        assert result.status == "enforced"

    def test_run_position_test_no_flips(self):
        samples = [
            {"prompt_id": f"p{i}", "verdict_original": "defect", "verdict_reversed": "defect"}
            for i in range(40)
        ]
        result = run_position_test(samples)
        assert result.verdict_flip_rate == 0.0
        assert result.status == "enforced"

    def test_run_position_test_partial(self):
        samples = [
            {"prompt_id": f"p{i}", "verdict_original": "defect",
             "verdict_reversed": ("no-defect" if i < 3 else "defect")}
            for i in range(40)
        ]
        result = run_position_test(samples)
        assert 0.05 < result.verdict_flip_rate <= 0.10
        assert result.status == "partial"

    def test_run_position_test_failed(self):
        samples = [
            {"prompt_id": f"p{i}", "verdict_original": "defect",
             "verdict_reversed": ("no-defect" if i < 8 else "defect")}
            for i in range(40)
        ]
        result = run_position_test(samples)
        assert result.verdict_flip_rate > 0.10
        assert result.status == "failed"

    def test_run_full_protocol_aggregate(self, tmp_path):
        # Construct a mixture: position enforced, verbosity partial, self-enh enforced
        samples = []
        for i in range(40):
            s = {
                "prompt_id": f"p{i}",
                "verdict_original": "defect",
                "verdict_reversed": "defect",
                "verbosity_flip": (i % 20 == 0),  # 2 flips out of 40 = 5% (partial)
                "self_enhancement_flip": False,
            }
            samples.append(s)

        out = tmp_path / "bias_summary.json"
        summary = run_full_protocol(samples, out_path=out)
        assert summary.aggregate_status in ("enforced", "partial", "failed")
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["freeze_tag"] == "vce-2026-09-20-frozen"
