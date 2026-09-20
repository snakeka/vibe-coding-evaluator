"""report.verdict_merger — verdict matrix construction (§B.5.1).

Combines the three pipeline outputs (SAST, Judge, Cross-Model) into
a single VerdictRow per prompt, classifying each as
``concurrence``, ``partial_concurrence``, ``divergence``, or
``incomplete`` per §3.6.

The triangulation rules are implemented in
``common.schema.VerdictRow.from_components``; this module is the
batch wrapper that builds the full matrix.
"""
from __future__ import annotations

from typing import Iterable

from common.schema import (
    CrossModelOutput,
    JudgeVerdict,
    SastResult,
    TriangulationClass,
    VerdictRow,
)


def build_verdict_matrix(
    prompts: list[dict],
    *,
    sast_results: dict[str, SastResult],
    judge_verdicts: dict[str, JudgeVerdict],
    cross_model_outputs: list[CrossModelOutput],
    freeze_tag: str,
) -> list[VerdictRow]:
    """Build the per-prompt verdict matrix (§B.5.1).

    Parameters
    ----------
    prompts : list[dict]
        Each entry has ``prompt_id``, ``language``, ``task``.
    sast_results : dict[str, SastResult]
        Keyed by prompt_id.
    judge_verdicts : dict[str, JudgeVerdict]
        Keyed by prompt_id.
    cross_model_outputs : list[CrossModelOutput]
        Across all (prompt × provider) pairs.
    freeze_tag : str
        For the provenance column.

    Returns
    -------
    list[VerdictRow]
        One row per prompt.
    """
    # Group cross-model outputs by prompt_id
    cm_by_prompt: dict[str, list[CrossModelOutput]] = {}
    for o in cross_model_outputs:
        cm_by_prompt.setdefault(o.prompt_id, []).append(o)

    rows: list[VerdictRow] = []
    for p in prompts:
        pid = p["prompt_id"]
        sast = sast_results.get(pid)
        judge = judge_verdicts.get(pid)
        cm = cm_by_prompt.get(pid, [])
        row = VerdictRow.from_components(
            prompt_id=pid,
            source_sha256=sast.source_sha256 if sast else "",
            language=p.get("language", ""),
            task=p.get("task", ""),
            sast=sast,
            judge=judge,
            cross_model_outputs=cm,
            freeze_tag=freeze_tag,
        )
        rows.append(row)
    return rows


def summarise(matrix: list[VerdictRow]) -> dict[str, int]:
    """Return a count of each TriangulationClass in the matrix."""
    counts = {c.value: 0 for c in TriangulationClass}
    for r in matrix:
        counts[r.triangulation.value] += 1
    return counts


def residual_cwes(matrix: list[VerdictRow]) -> dict[str, int]:
    """Count residual CWE flags by category (for §5.6 reporting)."""
    out: dict[str, int] = {}
    for r in matrix:
        if r.residual_flag:
            out[r.residual_flag] = out.get(r.residual_flag, 0) + 1
    return out
