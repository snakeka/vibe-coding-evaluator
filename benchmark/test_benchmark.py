"""benchmark tests — provider layer + dispatcher + normaliser.

Pure-Python unit tests. The actual litellm.completion call is mocked
so the suite is fast and CI-runnable without API keys.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from common.config import ModelsLock, ProviderSpec
from common.schema import CrossModelOutput
from benchmark.provider_layer import (
    RetryPolicy,
    RateLimitedError,
    _is_rate_limit,
    generate,
)
from benchmark.dispatcher import dispatch
from benchmark.normaliser import (
    static_label,
    annotate_with_static_label,
    normalise_batch,
    group_by_prompt,
    group_by_provider,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def models_lock() -> ModelsLock:
    return ModelsLock(
        freeze_tag="vce-2026-09-20-frozen",
        locked_at="2026-09-20T00:00:00Z",
        providers=(
            ProviderSpec(
                provider="ollama",
                model_id="qwen2.5-coder:32b",
                endpoint="http://localhost:11434",
                version_hash=None,
                locked_at="2026-09-20T00:00:00Z",
            ),
            ProviderSpec(
                provider="ollama",
                model_id="qwen2.5-coder:14b",
                endpoint="http://localhost:11434",
                version_hash=None,
                locked_at="2026-09-20T00:00:00Z",
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Retry policy tests
# ---------------------------------------------------------------------------


class TestRateLimitDetection:
    def test_429_is_rate_limit(self):
        assert _is_rate_limit(Exception("HTTP 429 Too Many Requests"))

    def test_rate_limit_text(self):
        assert _is_rate_limit(Exception("rate_limit_exceeded"))

    def test_other_error_not_rate_limit(self):
        assert not _is_rate_limit(Exception("connection refused"))

    def test_timeout_not_rate_limit(self):
        assert not _is_rate_limit(Exception("Read timed out"))


# ---------------------------------------------------------------------------
# Generate (with mocked litellm)
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generate_calls_litellm(self, models_lock):
        with patch("benchmark.provider_layer.litellm.completion") as mock:
            mock.return_value = {
                "choices": [
                    {"message": {"content": "def f(): return 1"}, "finish_reason": "stop"}
                ],
                "usage": {"total_tokens": 10},
            }
            text, meta = generate(
                "Write a function",
                model_id="qwen2.5-coder:32b",
                models_lock=models_lock,
                freeze_tag="vce-2026-09-20-frozen",
                prompt_id="p001",
            )
        assert "def f" in text
        assert meta["model_id"] == "qwen2.5-coder:32b"
        assert meta["latency_ms"] >= 0

    def test_generate_retries_on_429(self, models_lock):
        with patch("benchmark.provider_layer.litellm.completion") as mock:
            mock.side_effect = [
                Exception("HTTP 429 rate limit"),
                {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}], "usage": {}},
            ]
            with patch("benchmark.provider_layer._sleep_with_jitter"):
                text, meta = generate(
                    "p",
                    model_id="qwen2.5-coder:32b",
                    models_lock=models_lock,
                    freeze_tag="vce-2026-09-20-frozen",
                    prompt_id="p001",
                )
        assert text == "ok"
        assert mock.call_count == 2

    def test_generate_exhausts_retries(self, models_lock):
        with patch("benchmark.provider_layer.litellm.completion") as mock:
            mock.side_effect = Exception("HTTP 429 rate limit")
            with patch("benchmark.provider_layer._sleep_with_jitter"):
                with pytest.raises(RateLimitedError):
                    generate(
                        "p",
                        model_id="qwen2.5-coder:32b",
                        models_lock=models_lock,
                        freeze_tag="vce-2026-09-20-frozen",
                        prompt_id="p001",
                        retry_policy=RetryPolicy(max_attempts=2, initial_backoff_s=0.01),
                    )

    def test_generate_rejects_unknown_model(self, models_lock):
        with pytest.raises(KeyError):
            generate(
                "p",
                model_id="unknown-model",
                models_lock=models_lock,
                freeze_tag="vce-2026-09-20-frozen",
                prompt_id="p001",
            )

    def test_generate_rejects_freeze_mismatch(self, models_lock):
        with pytest.raises(ValueError, match="Freeze tag mismatch"):
            generate(
                "p",
                model_id="qwen2.5-coder:32b",
                models_lock=models_lock,
                freeze_tag="different-freeze",
                prompt_id="p001",
            )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class TestDispatcher:
    def test_dispatch_empty(self, models_lock):
        results = dispatch([], models_lock=models_lock, freeze_tag=models_lock.freeze_tag)
        assert results == []

    def test_dispatch_returns_one_per_prompt_provider(self, models_lock):
        prompts = [
            {"prompt_id": "p001", "prompt_text": "Write a function", "language": "python"},
            {"prompt_id": "p002", "prompt_text": "Write a class", "language": "python"},
        ]
        with patch("benchmark.dispatcher._dispatch_one") as mock:
            mock.return_value = CrossModelOutput(
                prompt_id="x",
                provider="ollama",
                model_id="qwen2.5-coder:32b",
                language="python",
                generated_source="ok",
                freeze_tag="vce-2026-09-20-frozen",
            )
            results = dispatch(
                prompts,
                models_lock=models_lock,
                freeze_tag=models_lock.freeze_tag,
                max_workers=2,
            )
        # 2 prompts × 2 models = 4 results
        assert len(results) == 4


# ---------------------------------------------------------------------------
# Normaliser
# ---------------------------------------------------------------------------


class TestNormaliser:
    def test_static_label_insecure_sql(self):
        assert static_label('query = f"SELECT * FROM x WHERE y = {name}"') == "defect"

    def test_static_label_insecure_password(self):
        assert static_label('password = "secret123"') == "defect"

    def test_static_label_insecure_eval(self):
        assert static_label("eval(user_input)") == "defect"

    def test_static_label_clean_code(self):
        assert static_label("def add(a, b): return a + b") == "no-defect"

    def test_static_label_empty_returns_inconclusive(self):
        assert static_label("") == "inconclusive"

    def test_annotate_sets_static_label(self):
        out = CrossModelOutput(
            prompt_id="p1",
            provider="ollama",
            model_id="qwen2.5-coder:32b",
            language="python",
            generated_source='password = "secret"',
            completion_metadata={},
            freeze_tag="vce-2026-09-20-frozen",
        )
        annotated = annotate_with_static_label(out)
        assert annotated.completion_metadata["static_label"] == "defect"

    def test_normalise_batch(self):
        outs = [
            CrossModelOutput(
                prompt_id="p1",
                provider="ollama",
                model_id="m",
                language="python",
                generated_source='password = "x"',
                completion_metadata={},
                freeze_tag="vce-2026-09-20-frozen",
            )
        ]
        [a] = normalise_batch(outs)
        assert a.completion_metadata["static_label"] == "defect"

    def test_group_by_prompt(self):
        outs = [
            CrossModelOutput(prompt_id="p1", provider="ollama", model_id="m1", language="python", generated_source="", freeze_tag="t"),
            CrossModelOutput(prompt_id="p1", provider="openai", model_id="m2", language="python", generated_source="", freeze_tag="t"),
            CrossModelOutput(prompt_id="p2", provider="ollama", model_id="m1", language="python", generated_source="", freeze_tag="t"),
        ]
        grouped = group_by_prompt(outs)
        assert len(grouped) == 2
        assert len(grouped["p1"]) == 2

    def test_group_by_provider(self):
        outs = [
            CrossModelOutput(prompt_id="p1", provider="ollama", model_id="m1", language="python", generated_source="", freeze_tag="t"),
            CrossModelOutput(prompt_id="p1", provider="openai", model_id="m2", language="python", generated_source="", freeze_tag="t"),
            CrossModelOutput(prompt_id="p2", provider="ollama", model_id="m1", language="python", generated_source="", freeze_tag="t"),
        ]
        grouped = group_by_provider(outs)
        assert len(grouped) == 2
        assert len(grouped["ollama"]) == 2
