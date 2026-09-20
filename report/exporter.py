"""report.exporter — CSV + JSON + dashboard export (§B.5.3).

Per §B.5.3, the Report Generator writes three artefacts per run:

* verdict_matrix.csv   — the per-prompt verdict matrix (one row per prompt)
* verdict_matrix.json  — same data in structured JSON form
* dashboard.html       — a stakeholder-facing HTML view (consumed by Ch 6)

All three are sealed into the per-run ``manifest.sha256`` by
``scripts/generate_manifest.py``.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from common.schema import TriangulationClass, VerdictRow


def export_csv(
    matrix: list[VerdictRow],
    path: Path | str,
) -> Path:
    """Write the verdict matrix as CSV (§B.5.3)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "prompt_id",
        "language",
        "task",
        "source_sha256",
        "freeze_tag",
        "sast_verdict",
        "sast_findings_count",
        "judge_verdict",
        "judge_cwe",
        "judge_severity",
        "judge_confidence",
        "cross_model_defect_yes",
        "cross_model_defect_no",
        "cross_model_defect_inconclusive",
        "triangulation",
        "residual_flag",
    ]

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in matrix:
            writer.writerow({
                "prompt_id": r.prompt_id,
                "language": r.language,
                "task": r.task,
                "source_sha256": r.source_sha256,
                "freeze_tag": r.freeze_tag,
                "sast_verdict": r.sast_verdict or "",
                "sast_findings_count": r.sast_findings_count,
                "judge_verdict": r.judge_verdict.value if r.judge_verdict else "",
                "judge_cwe": r.judge_cwe or "",
                "judge_severity": r.judge_severity.value if r.judge_severity else "",
                "judge_confidence": r.judge_confidence if r.judge_confidence is not None else "",
                "cross_model_defect_yes": r.cross_model_defect_yes,
                "cross_model_defect_no": r.cross_model_defect_no,
                "cross_model_defect_inconclusive": r.cross_model_defect_inconclusive,
                "triangulation": r.triangulation.value,
                "residual_flag": r.residual_flag or "",
            })
    return path


def export_json(
    matrix: list[VerdictRow],
    path: Path | str,
    *,
    summary: dict[str, int] | None = None,
    residual: dict[str, int] | None = None,
) -> Path:
    """Write the verdict matrix as JSON (§B.5.3)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "rows": [r.model_dump(mode="json") for r in matrix],
        "n_rows": len(matrix),
    }
    if summary is not None:
        payload["summary"] = summary
    if residual is not None:
        payload["residual_cwes"] = residual

    path.write_text(json.dumps(payload, indent=2, default=str))
    return path


def render_dashboard(
    matrix: list[VerdictRow],
    path: Path | str,
    *,
    title: str = "Vibe Coding Evaluation — Verdict Matrix Dashboard",
) -> Path:
    """Render an HTML dashboard for stakeholder review (§B.5.3).

    The dashboard is intentionally minimal (a single HTML file with
    embedded CSS) so it can be opened in any browser without a
    server. It surfaces:

    * Summary counts (concurrence / partial / divergence / incomplete)
    * Residual CWE breakdown
    * A searchable, sortable table of every row

    No external dependencies — just stdlib + the embedded template below.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Summary counts
    counts = {c.value: 0 for c in TriangulationClass}
    for r in matrix:
        counts[r.triangulation.value] += 1

    # Residual CWE counts
    residuals: dict[str, int] = {}
    for r in matrix:
        if r.residual_flag:
            residuals[r.residual_flag] = residuals.get(r.residual_flag, 0) + 1

    # Build the rows HTML
    rows_html: list[str] = []
    for r in matrix:
        tri_class = r.triangulation.value
        tri_color = {
            "concurrence": "#16a34a",
            "partial_concurrence": "#f59e0b",
            "divergence": "#dc2626",
            "incomplete": "#6b7280",
        }.get(tri_class, "#000")
        rows_html.append(
            f"<tr>"
            f"<td><code>{r.prompt_id}</code></td>"
            f"<td>{r.language}</td>"
            f"<td>{r.task}</td>"
            f"<td>{r.sast_verdict or '—'}</td>"
            f"<td>{r.judge_verdict.value if r.judge_verdict else '—'}</td>"
            f"<td>{r.judge_cwe or '—'}</td>"
            f"<td>{r.cross_model_defect_yes}/{r.cross_model_defect_no}/{r.cross_model_defect_inconclusive}</td>"
            f'<td style="background:{tri_color}22;border-left:3px solid {tri_color};padding-left:6px">{tri_class}</td>'
            f"<td>{r.residual_flag or '—'}</td>"
            f"</tr>"
        )

    residual_html = (
        "".join(
            f"<li><code>{cwe}</code>: {n}</li>"
            for cwe, n in sorted(residuals.items(), key=lambda kv: -kv[1])
        )
        if residuals
        else "<li>No residual flags.</li>"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2em; color: #1f2937; }}
  h1 {{ font-size: 1.5em; }}
  h2 {{ font-size: 1.1em; margin-top: 2em; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.3em; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1em; margin: 1em 0; }}
  .card {{ background: #f9fafb; border: 1px solid #e5e7eb; padding: 1em; border-radius: 4px; }}
  .card h3 {{ margin: 0 0 0.4em 0; font-size: 0.9em; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .n {{ font-size: 1.8em; font-weight: bold; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
  th, td {{ padding: 6px 8px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
  th {{ background: #f9fafb; font-weight: 600; }}
  code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 0.9em; }}
  .residual {{ list-style: square inside; padding-left: 0; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Total rows: <strong>{len(matrix)}</strong></p>

<h2>Summary</h2>
<div class="summary">
  <div class="card"><h3>Concurrence</h3><div class="n" style="color:#16a34a">{counts["concurrence"]}</div></div>
  <div class="card"><h3>Partial Concurrence</h3><div class="n" style="color:#f59e0b">{counts["partial_concurrence"]}</div></div>
  <div class="card"><h3>Divergence</h3><div class="n" style="color:#dc2626">{counts["divergence"]}</div></div>
  <div class="card"><h3>Incomplete</h3><div class="n" style="color:#6b7280">{counts["incomplete"]}</div></div>
</div>

<h2>Residual CWE breakdown</h2>
<ul class="residual">{residual_html}</ul>

<h2>Per-prompt verdict matrix</h2>
<table>
  <thead>
    <tr>
      <th>Prompt ID</th><th>Lang</th><th>Task</th>
      <th>SAST</th><th>Judge</th><th>Judge CWE</th>
      <th>Cross-model (yes/no/inc)</th><th>Triangulation</th><th>Residual</th>
    </tr>
  </thead>
  <tbody>
    {"".join(rows_html)}
  </tbody>
</table>

<footer style="margin-top:3em;color:#6b7280;font-size:0.85em">
  <p>Generated by <code>vibe-coding-evaluator</code> · freeze_tag: <code>{matrix[0].freeze_tag if matrix else "n/a"}</code></p>
</footer>
</body>
</html>"""

    path.write_text(html)
    return path
