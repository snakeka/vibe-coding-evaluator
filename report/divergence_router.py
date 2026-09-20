"""report.divergence_router — INCOMPLETE flag + human review queue (§B.5.2).

Flags divergent and INCOMPLETE rows for human review (§3.7 sealing:
no imputation of missing values). Writes a JSON queue file at
``results/<run-id>/human_review_queue.json`` so the §6.4 stakeholder
view can route these rows to the right reviewer.

The router is intentionally conservative — it never reclassifies a
row, only tags it. Reclassification is the auditor's responsibility.
"""
from __future__ import annotations

import json
from pathlib import Path

from common.schema import TriangulationClass, VerdictRow


def route_incomplete_rows(
    matrix: list[VerdictRow],
    *,
    out_path: Path | str | None = None,
) -> list[VerdictRow]:
    """Tag divergent and INCOMPLETE rows for human review.

    Returns the list of rows that need human attention. Optionally
    writes a JSON queue file.
    """
    queue: list[VerdictRow] = []
    for r in matrix:
        if r.triangulation in (
            TriangulationClass.DIVERGENCE,
            TriangulationClass.INCOMPLETE,
        ):
            queue.append(r)

    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "n_total": len(matrix),
            "n_flagged": len(queue),
            "rows": [r.model_dump(mode="json") for r in queue],
        }
        out_path.write_text(json.dumps(payload, indent=2))

    return queue


def queue_by_reason(
    matrix: list[VerdictRow],
) -> dict[str, list[VerdictRow]]:
    """Group flagged rows by their reason for human review (§B.5.2)."""
    out: dict[str, list[VerdictRow]] = {
        "incomplete": [],
        "divergence": [],
        "residual_flag": [],
    }
    for r in matrix:
        if r.triangulation == TriangulationClass.INCOMPLETE:
            out["incomplete"].append(r)
        elif r.triangulation == TriangulationClass.DIVERGENCE:
            out["divergence"].append(r)
        if r.residual_flag:
            out["residual_flag"].append(r)
    return out
