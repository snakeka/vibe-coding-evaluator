"""judge.orchestrator — LiteLLM wrapper exposing ``judge(...)`` (§B.2.1).

The LLM-as-Judge pipeline is implemented as a Python module wrapping
the LiteLLM library, which exposes a uniform calling interface to
OpenAI, Anthropic, Mistral, and any OpenAI-compatible endpoint such
as Ollama. The Judge therefore contains no provider-specific code
paths.

The orchestrator applies the three bias controls in order (§B.4):

1. ``apply_position`` — shuffle the candidates under a §3.5-seeded
   ordering key (B.4.1).
2. ``apply_self_enhancement`` — replace the source's model_id with
   a cryptographic provider tag (B.4.3). The leakage strings are
   captured for the post-call audit-log verification.
3. ``apply_verbosity`` — enforce the ≈200-token response cap via
   ``max_tokens=224`` (B.4.2).

Then the orchestrator invokes LiteLLM with ``temperature=0`` (B.6.4)
and, where supported, an explicit ``seed=`` value. The response is
parsed by ``prompt_template.parse_response`` and emitted as a
``JudgeVerdict``.

Every call records a full ``AuditRecord`` via ``judge.audit_log``.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import litellm  # type: ignore[import-not-found]

from common.config import ModelsLock, ProviderSpec, get_api_key
from common.hashing import seeded_rng, sha256_str
from common.schema import JudgeVerdict, JudgeLabel, Severity
from judge.audit_log import AuditLog, make_audit_record
from judge.bias_controls import apply_position, apply_self_enhancement, apply_verbosity
from judge.prompt_template import (
    PREAMBLE,
    build_messages,
    make_provider_tag,
    parse_response,
)


def _build_candidate_list(
    sast_findings: list[dict],
) -> list[dict]:
    """Build the candidate list passed to the Judge.

    Per §3.4 the list includes the SAST-derived findings plus an
    explicit "no-finding" baseline cell, so the Judge is never
    forced into a binary defect / no-defect choice on sparse SAST
    output.
    """
    candidates = list(sast_findings)
    candidates.append(
        {
            "tool": "baseline",
            "rule_id": "none",
            "line": 0,
            "message": "No defect detected by static analysis.",
            "cwe": None,
            "severity": None,
        }
    )
    return candidates


def _resolve_seed(
    provider_spec: ProviderSpec,
    freeze_tag: str,
    prompt_id: str,
) -> int | None:
    """Resolve the per-call seed value (§B.6.4).

    Per §B.6.4, providers that support ``seed=`` get an explicit
    value drawn from a §3.5-seeded RNG; providers that do not get
    ``None`` (logged as ``seed=null`` in the audit log).
    """
    supports_seed = provider_spec.provider in {"openai", "mistral"}
    if not supports_seed:
        return None
    rng = seeded_rng(freeze_tag, prompt_id + "::seed")
    return rng.randrange(2**31)


def judge(
    *,
    prompt_id: str,
    source_code: str,
    sast_findings: list[dict],
    source_model_id: str,
    judge_provider_spec: ProviderSpec,
    freeze_tag: str,
    audit_log: AuditLog,
    litellm_kwargs: dict[str, Any] | None = None,
) -> JudgeVerdict:
    """Invoke the LLM-as-Judge and return a JudgeVerdict.

    Parameters
    ----------
    prompt_id : str
        Freeze-stable prompt identifier.
    source_code : str
        The code sample under review.
    sast_findings : list[dict]
        Each entry has ``tool``, ``rule_id``, ``line``, ``message``, ``cwe``, ``severity``.
    source_model_id : str
        The model_id of the *source* (under review) — used for the
        self-enhancement blinding tag.
    judge_provider_spec : ProviderSpec
        The provider spec for the *Judge* model (which judges, not
        which is under review).
    freeze_tag : str
        From models.lock.
    audit_log : AuditLog
        Open audit log handle; one record per call is appended.
    litellm_kwargs : dict[str, Any] | None
        Optional extra kwargs to pass to litellm.completion (e.g.
        ``{"api_base": ..., "timeout": ...}``).

    Returns
    -------
    JudgeVerdict
        The parsed verdict.
    """
    # ------------------------------------------------------------------ #
    # 1. Apply position bias control                                     #
    # ------------------------------------------------------------------ #
    candidates = _build_candidate_list(sast_findings)
    shuffled, ordering_key = apply_position(
        candidates, freeze_tag, prompt_id, ordering_key=None
    )

    # ------------------------------------------------------------------ #
    # 2. Apply self-enhancement blinding                                #
    # ------------------------------------------------------------------ #
    provider_tag = make_provider_tag(source_model_id)
    messages = build_messages(source_code, shuffled, provider_tag)

    # ------------------------------------------------------------------ #
    # 3. Apply verbosity cap                                             #
    # ------------------------------------------------------------------ #
    generation_params: dict[str, Any] = {
        "temperature": 0.0,
        "top_p": 1.0,
    }
    generation_params = apply_verbosity(generation_params, cap=224)

    # ------------------------------------------------------------------ #
    # 4. Resolve per-call seed                                           #
    # ------------------------------------------------------------------ #
    seed = _resolve_seed(judge_provider_spec, freeze_tag, prompt_id)

    # ------------------------------------------------------------------ #
    # 5. Build the LiteLLM call                                          #
    # ------------------------------------------------------------------ #
    call_kwargs: dict[str, Any] = {
        "model": f"{judge_provider_spec.provider}/{judge_provider_spec.model_id}",
        "messages": messages,
        **generation_params,
    }
    if seed is not None:
        call_kwargs["seed"] = seed
    if judge_provider_spec.api_base:
        call_kwargs["api_base"] = judge_provider_spec.api_base
    if litellm_kwargs:
        call_kwargs.update(litellm_kwargs)

    # ------------------------------------------------------------------ #
    # 6. Invoke LiteLLM and capture the response                         #
    # ------------------------------------------------------------------ #
    t0 = time.monotonic()
    response = litellm.completion(**call_kwargs)
    response_text = response["choices"][0]["message"]["content"]
    latency_ms = int((time.monotonic() - t0) * 1000)

    # ------------------------------------------------------------------ #
    # 7. Parse the response into the §B.4.2 schema                       #
    # ------------------------------------------------------------------ #
    parsed = parse_response(response_text)

    # ------------------------------------------------------------------ #
    # 8. Build the JudgeVerdict                                          #
    # ------------------------------------------------------------------ #
    verdict = JudgeVerdict(
        prompt_id=prompt_id,
        source_sha256=sha256_str(source_code),
        label=JudgeLabel(parsed["verdict"]),
        cwe=parsed["cwe"],
        severity=Severity(parsed["severity"]) if parsed["severity"] else None,
        confidence=parsed["confidence"],
        evidence=parsed["evidence"],
        provider=judge_provider_spec.provider,
        model_id=judge_provider_spec.model_id,
        freeze_tag=freeze_tag,
        audit_log_ref=None,  # set by the caller after the audit record is written
    )

    # ------------------------------------------------------------------ #
    # 9. Write the audit record                                          #
    # ------------------------------------------------------------------ #
    prompt_text = PREAMBLE + "\n\n" + (
        messages[1]["content"] if len(messages) > 1 else ""
    )
    leakage_strings = [source_model_id]
    record = make_audit_record(
        caller="orchestrator",
        prompt_id=prompt_id,
        freeze_tag=freeze_tag,
        provider=judge_provider_spec.provider,
        model_id=judge_provider_spec.model_id,
        seed=seed,
        ordering_key=ordering_key,
        response=response_text,
        prompt_text=prompt_text,
        leakage_strings=leakage_strings,
        start_time=t0,
        metadata={
            "latency_ms_override": latency_ms,
            "source_model_id": source_model_id,
        },
    )
    audit_log.write(record)

    if not record.leakage_check_passed:
        raise RuntimeError(
            f"§B.4.3 self-enhancement leakage detected for prompt {prompt_id}: "
            f"{record.leakage_violations}. Aborting run per §3.7."
        )

    return verdict
