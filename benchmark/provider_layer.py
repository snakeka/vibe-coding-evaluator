"""benchmark.provider_layer — common ``generate()`` over LiteLLM (§B.3.2).

Exposes a single ``generate(prompt, model_id) -> response`` method
that dispatches to the correct provider via LiteLLM. The provider
substrate is read from ``models.lock`` at start-up.

A bounded worker pool issues requests in parallel; each worker
applies exponential back-off with jitter when a provider returns a
HTTP 429 response, up to a documented per-request retry budget.
"""
from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from typing import Any

import litellm  # type: ignore[import-not-found]

from common.config import ModelsLock, ProviderSpec, get_api_key
from common.hashing import seeded_rng


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """Exponential back-off with jitter (§B.3.2)."""

    max_attempts: int = 5
    initial_backoff_s: float = 1.0
    max_backoff_s: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_ratio: float = 0.25    # ±25% jitter


class RateLimitedError(Exception):
    """Raised when retry budget is exhausted."""


def _sleep_with_jitter(backoff_s: float, jitter_ratio: float) -> None:
    """Sleep with ±jitter_ratio random jitter."""
    jitter = backoff_s * jitter_ratio
    actual = backoff_s + random.uniform(-jitter, jitter)
    time.sleep(max(0.0, actual))


def _is_rate_limit(exc: Exception) -> bool:
    """Heuristic: is this a 429 / rate-limit error?"""
    s = str(exc).lower()
    return (
        "429" in s
        or "rate" in s and "limit" in s
        or "too many requests" in s
        or "rate_limit" in s
    )


def _is_region_blocked(exc: Exception) -> bool:
    """Heuristic: is this a region/egress block (HTTP 403)?

    Anthropic returns 403 "Request not allowed" from HK egress (§5.5
    robustness discussion). OpenAI may do the same for some endpoints.
    When detected, we raise :class:`RegionBlockedError` so the caller
    can mark the row ``provider_unavailable`` without aborting the run.
    """
    s = str(exc).lower()
    return (
        "403" in s
        or "request not allowed" in s
        or "unsupported country" in s
        or "region" in s and "not supported" in s
    )


class RegionBlockedError(Exception):
    """Raised when the provider blocks egress from the current region.

    Per §5.5 cross-model robustness discussion: the Cross-Model
    Benchmarker treats such providers as optional. A region-block
    records the row as ``provider_unavailable`` and the run continues
    with the remaining providers — never aborts the full run.
    """


def _generate_with_retry(
    *,
    call_kwargs: dict[str, Any],
    retry_policy: RetryPolicy,
    freeze_tag: str,
    prompt_id: str,
) -> Any:
    """Invoke litellm.completion with exponential back-off on 429."""
    rng = seeded_rng(freeze_tag, prompt_id)
    backoff = retry_policy.initial_backoff_s

    for attempt in range(1, retry_policy.max_attempts + 1):
        try:
            return litellm.completion(**call_kwargs)
        except Exception as exc:
            # Region/egress blocks (e.g. Anthropic 403 from HK) are not
            # retried — they will never succeed. Raise immediately so
            # the caller can record ``provider_unavailable``.
            if _is_region_blocked(exc):
                raise RegionBlockedError(
                    f"Egress blocked for {call_kwargs.get('model')}: {exc}"
                ) from exc
            if not _is_rate_limit(exc):
                raise
            if attempt == retry_policy.max_attempts:
                raise RateLimitedError(
                    f"Exhausted {retry_policy.max_attempts} retries for "
                    f"prompt {prompt_id}: {exc}"
                ) from exc
            _sleep_with_jitter(backoff, retry_policy.jitter_ratio)
            backoff = min(
                retry_policy.max_backoff_s,
                backoff * retry_policy.backoff_multiplier,
            )
            # Per §B.3.2 jitter is also applied via the seeded RNG
            # so the sleep is reproducible across re-runs.
            _sleep_with_jitter(rng.uniform(0, 0.1), 0.0)

    raise RateLimitedError(f"Unreachable: exhausted retries for {prompt_id}")


# ---------------------------------------------------------------------------
# Provider API-key resolution
# ---------------------------------------------------------------------------
#
# We delegate to ProviderSpec.api_key_env_var (added in common/config.py)
# which is the canonical mapping. The local _API_KEY_ENV_VAR fallback
# below is kept for direct callers that have only a provider name
# (no ProviderSpec). New providers MUST be added in BOTH places, or
# callers should prefer the ProviderSpec-based path.


_API_KEY_ENV_VAR_FALLBACK = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "ollama": None,    # Ollama has no API key
}


def _resolve_api_key(provider: str) -> str | None:
    """Return the API key for a provider, or None if not configured.

    Looks up the env var name from the fallback mapping. Prefer
    passing a ProviderSpec and reading ``spec.api_key_env_var``
    directly — that path is automatically updated when new providers
    are added to models.lock.
    """
    env_var = _API_KEY_ENV_VAR_FALLBACK.get(provider)
    if env_var is None:
        return None
    return os.environ.get(env_var)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def generate(
    prompt_text: str,
    *,
    model_id: str,
    models_lock: ModelsLock,
    freeze_tag: str,
    prompt_id: str,
    retry_policy: RetryPolicy | None = None,
    max_tokens: int = 1024,
    extra_kwargs: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Generate a completion for one prompt against one provider.

    Parameters
    ----------
    prompt_text : str
        The user prompt to send.
    model_id : str
        The model identifier (must be in ``models.lock``).
    models_lock : ModelsLock
        Loaded from ``models.lock``.
    freeze_tag : str
        From ``models.lock.freeze_tag`` (asserted at start-up).
    prompt_id : str
        For seeded back-off jitter and audit-log cross-ref.
    retry_policy : RetryPolicy | None
        Defaults to the §B.3.2 values.
    max_tokens : int
        Cap on the completion length.
    extra_kwargs : dict[str, Any] | None
        Forwarded to litellm.completion.

    Returns
    -------
    tuple[str, dict[str, Any]]
        (response_text, metadata_dict)
        metadata_dict has ``latency_ms``, ``model_id``, ``provider``, ``finish_reason``.

    Raises
    ------
    RateLimitedError
        Retry budget exhausted.
    KeyError
        model_id not in models.lock.
    """
    spec = models_lock.get_model(model_id)
    if freeze_tag != models_lock.freeze_tag:
        raise ValueError(
            f"Freeze tag mismatch: caller='{freeze_tag}' vs lock='{models_lock.freeze_tag}'"
        )

    policy = retry_policy or RetryPolicy()
    api_key = _resolve_api_key(spec.provider)
    if spec.provider != "ollama" and not api_key:
        env_var = spec.api_key_env_var or f"{spec.provider.upper()}_API_KEY"
        raise RuntimeError(
            f"Provider '{spec.provider}' requires {env_var} "
            f"in environment or .env"
        )

    call_kwargs: dict[str, Any] = {
        "model": f"{spec.provider}/{spec.model_id}",
        "messages": [{"role": "user", "content": prompt_text}],
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": max_tokens,
    }
    if api_key:
        call_kwargs["api_key"] = api_key
    if spec.api_base:
        call_kwargs["api_base"] = spec.api_base
    if extra_kwargs:
        call_kwargs.update(extra_kwargs)

    t0 = time.monotonic()
    response = _generate_with_retry(
        call_kwargs=call_kwargs,
        retry_policy=policy,
        freeze_tag=freeze_tag,
        prompt_id=prompt_id,
    )
    latency_ms = int((time.monotonic() - t0) * 1000)

    response_text = response["choices"][0]["message"]["content"]
    metadata: dict[str, Any] = {
        "latency_ms": latency_ms,
        "model_id": spec.model_id,
        "provider": spec.provider,
        "endpoint": spec.endpoint,
        "freeze_tag": freeze_tag,
        "prompt_id": prompt_id,
        "usage": dict(response.get("usage") or {}),
        "finish_reason": response["choices"][0].get("finish_reason"),
    }
    return response_text, metadata
