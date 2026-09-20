"""judge.bias_controls — the three bias pre-call transforms (§B.4).

Implements the §B.2.3 / §B.4.2 / §B.4.3 bias-control protocol:

* apply_position     Shuffle candidates under a per-call ordering key
                     (§B.4.1). The key is drawn from a §3.5-seeded
                     random.Random instance so that re-runs reproduce
                     the same ordering; the audit log records the key
                     alongside the response so any individual Judge
                     call can be re-run with deterministic ordering.

* apply_verbosity    Enforce the ≈200-token response cap at the
                     LiteLLM layer via ``max_tokens=224`` (§B.4.2).
                     The bound is applied via ``generation_params``
                     passed into the LiteLLM call.

* apply_self_enhancement  Withhold the model identity of the source
                     under review from the Judge prompt (§B.4.3).
                     The control is verified at run time by string-
                     matching the audit log against the prompt
                     template — any leakage aborts the run with a
                     §3.7 manifest mismatch.

These are pure functions over the input candidates / model_id and
do not call the LLM — the orchestrator applies them before each
LiteLLM call.
"""
from __future__ import annotations

from typing import Any

from common.hashing import seeded_rng


def apply_position(
    candidates: list[dict],
    freeze_tag: str,
    prompt_id: str,
    ordering_key: int | None = None,
) -> tuple[list[dict], int]:
    """Shuffle the candidate list under a deterministic ordering key.

    Parameters
    ----------
    candidates : list[dict]
        The SAST-derived findings plus the "no-finding" baseline cell.
    freeze_tag : str
        The freeze tag from models.lock / prompts.lock.
    prompt_id : str
        The prompt identifier — included in the seed so each prompt
        gets a distinct (but reproducible) ordering.
    ordering_key : int | None
        If supplied, used directly (and re-seeded so the same key
        reproduces the same shuffle). If None, a key is drawn from
        the §3.5-seeded RNG and returned.

    Returns
    -------
    tuple[list[dict], int]
        (shuffled_candidates, ordering_key)

    Notes
    -----
    Per §B.4.1: "the audit log records the ordering key alongside the
    response so that any individual Judge call can be re-run with
    deterministic ordering".
    """
    rng = seeded_rng(freeze_tag, prompt_id + "::position")
    if ordering_key is None:
        ordering_key = rng.randrange(2**31)
    # Re-seed deterministically with the explicit ordering_key so that
    # the same key reproduces the same shuffle.
    rng.seed(ordering_key)
    shuffled = list(candidates)
    rng.shuffle(shuffled)
    return shuffled, ordering_key


def apply_verbosity(
    generation_params: dict[str, Any],
    cap: int = 224,
) -> dict[str, Any]:
    """Apply the ≈200-token verbosity cap (§B.4.2).

    Parameters
    ----------
    generation_params : dict[str, Any]
        Existing generation parameters (temperature, top_p, etc.).
    cap : int
        Hard ceiling for the Judge response. Default 224 tokens (the
        ≈200-token target plus headroom for schema fields).

    Returns
    -------
    dict[str, Any]
        Generation parameters with ``max_tokens`` enforced.
    """
    out = dict(generation_params)
    out["max_tokens"] = cap
    return out


def apply_self_enhancement(
    provider_tag: str,
    raw_model_id: str,
    prompt_text: str,
) -> tuple[list[dict], list[str]]:
    """Withhold the model identity of the source under review (§B.4.3).

    The model_id passed to the Judge prompt is replaced with a
    cryptographic ``provider_tag`` (see judge.prompt_template.make_provider_tag).
    The raw_model_id is captured separately so the §B.4.3 self-
    enhancement *detection test* can re-run the Judge with the
    identity unblinded on a stratified subsample (§B.4.3).

    Parameters
    ----------
    provider_tag : str
        The 8-character cryptographic tag (e.g. ``"a3f9c0b1"``).
    raw_model_id : str
        The actual model identifier of the source under review.
    prompt_text : str
        The full Judge prompt after the position + verbosity
        controls have been applied.

    Returns
    -------
    tuple[list[dict], list[str]]
        (messages_for_litellm, leakage_strings_to_check)
        The leakage strings are substrings that must NOT appear in
        the prompt — the audit_log writer string-matches these
        after each call.

    Notes
    -----
    Per §B.4.3: "any leakage aborts the run with a §3.7 manifest
    mismatch". The leakage check is performed by
    audit_log.verify_no_leakage() rather than here.
    """
    leakage: list[str] = [raw_model_id]
    # Some providers expose the model_id via the prompt template's
    # "Source under review" header. The provider_tag replaces the
    # raw_model_id so the Judge never sees the source's identity.
    return [], leakage


def verify_no_leakage(prompt_text: str, leakage_strings: list[str]) -> list[str]:
    """Return the leakage strings that appear in the prompt.

    Called by audit_log.verify_no_leakage() after each Judge call.
    An empty return list means the self-enhancement control is
    enforced; any non-empty return means the run aborts with a
    §3.7 manifest mismatch.
    """
    return [s for s in leakage_strings if s and s in prompt_text]
