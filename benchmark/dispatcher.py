"""benchmark.dispatcher — parallel issuance of frozen prompts (§B.3.1).

Issues the §3.5 frozen prompt set to all four providers via
ThreadPoolExecutor. With 200 prompts sent to four providers, serial
execution would dominate the wall-clock cost of the empirical run and
delay rate-limit recovery — so requests are dispatched in parallel.

Per-provider retry budget is enforced in
``benchmark.provider_layer._generate_with_retry``.
"""
from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path
from typing import Any

from common.config import ModelsLock
from common.hashing import sha256_str
from common.schema import CrossModelOutput
from benchmark.provider_layer import RateLimitedError, RetryPolicy, generate


def _dispatch_one(
    prompt_text: str,
    *,
    model_id: str,
    models_lock: ModelsLock,
    freeze_tag: str,
    prompt_id: str,
    max_tokens: int,
) -> CrossModelOutput:
    """Dispatch one prompt to one provider. Returns CrossModelOutput."""
    spec = models_lock.get_model(model_id)
    try:
        text, meta = generate(
            prompt_text,
            model_id=model_id,
            models_lock=models_lock,
            freeze_tag=freeze_tag,
            prompt_id=prompt_id,
            max_tokens=max_tokens,
        )
        return CrossModelOutput(
            prompt_id=prompt_id,
            provider=spec.provider,
            model_id=model_id,
            language="",  # filled by caller from prompts.lock
            generated_source=text,
            completion_metadata=meta,
            latency_ms=meta.get("latency_ms", 0),
            freeze_tag=freeze_tag,
        )
    except RateLimitedError as exc:
        return CrossModelOutput(
            prompt_id=prompt_id,
            provider=spec.provider,
            model_id=model_id,
            language="",
            generated_source="",
            completion_metadata={},
            latency_ms=0,
            freeze_tag=freeze_tag,
            error=f"rate_limit_exhausted: {exc}",
        )
    except Exception as exc:
        return CrossModelOutput(
            prompt_id=prompt_id,
            provider=spec.provider,
            model_id=model_id,
            language="",
            generated_source="",
            completion_metadata={},
            latency_ms=0,
            freeze_tag=freeze_tag,
            error=f"{type(exc).__name__}: {exc}",
        )


def dispatch(
    prompts: list[dict],
    *,
    models_lock: ModelsLock,
    freeze_tag: str,
    model_ids: list[str] | None = None,
    max_workers: int = 8,
    max_tokens: int = 1024,
) -> list[CrossModelOutput]:
    """Issue every (prompt × model_id) pair in parallel.

    Parameters
    ----------
    prompts : list[dict]
        Each entry has ``prompt_id``, ``prompt_text``, ``language``.
    models_lock : ModelsLock
        From ``models.lock``.
    freeze_tag : str
        From ``models_lock.freeze_tag``.
    model_ids : list[str] | None
        Subset of models_lock to dispatch to. Defaults to all providers.
    max_workers : int
        Thread pool size. 8 is a sensible default for 4-provider fan-out.
    max_tokens : int
        Per-call completion length cap.

    Returns
    -------
    list[CrossModelOutput]
        One per (prompt × model_id). Failures recorded as
        ``CrossModelOutput(error=...)``.
    """
    if model_ids is None:
        model_ids = [p.model_id for p in models_lock.providers]

    jobs = [
        (p, m) for p in prompts for m in model_ids
    ]

    results: list[CrossModelOutput] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _dispatch_one,
                p["prompt_text"],
                model_id=m,
                models_lock=models_lock,
                freeze_tag=freeze_tag,
                prompt_id=p["prompt_id"],
                max_tokens=max_tokens,
            ): (p, m)
            for (p, m) in jobs
        }
        for fut in concurrent.futures.as_completed(futures):
            p, m = futures[fut]
            out = fut.result()
            out.language = p.get("language", "")
            results.append(out)

    return results
