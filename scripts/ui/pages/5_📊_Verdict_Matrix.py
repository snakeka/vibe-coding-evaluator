"""Streamlit page — 📊 Verdict matrix + dashboard.

Builds the per-prompt verdict matrix (§B.5.1) by running the four
pipelines in sequence (SAST → Judge → Benchmark → Verdict Merger)
and renders the table + the HTML dashboard for stakeholder review.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from common.config import (
    assert_freeze_consistent,
    load_models_lock,
    load_prompts_lock,
)
from common.fixtures import ALL_SAMPLES, SAMPLE_1_SQLI, SAMPLE_2_HARDCODED, SAMPLE_3_VALIDATION
from common.schema import JudgeLabel, Severity
from judge.audit_log import AuditLog
from judge.orchestrator import judge as judge_call
from judge.prompt_template import parse_response
from benchmark.normaliser import normalise_batch
from report.divergence_router import route_incomplete_rows
from report.exporter import export_csv, export_json, render_dashboard
from report.verdict_merger import build_verdict_matrix, residual_cwes, summarise
from sast.runner import run_sast

st.set_page_config(page_title="Verdict matrix", page_icon="📊", layout="wide")

st.title("📊 Verdict matrix")
st.markdown(
    """
    Run the four pipelines on one or all three illustrative samples
    and assemble the per-prompt verdict matrix (§B.5.1). The matrix
    classifies each prompt as **concurrence** / **partial concurrence**
    / **divergence** based on agreement between SAST, Judge, and the
    cross-model benchmark.
    """
)

st.divider()

# -----------------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Configuration")
    sample_choice = st.radio(
        "Sample scope",
        options=["All 3 samples", "Single sample"],
        index=0,
    )

    if sample_choice == "Single sample":
        which = st.radio(
            "Which sample?",
            options=["p001 — SQLi", "p002 — Hardcoded pwd", "p003 — Missing validation"],
            index=0,
        )
        if which.startswith("p001"):
            selected = [SAMPLE_1_SQLI]
        elif which.startswith("p002"):
            selected = [SAMPLE_2_HARDCODED]
        else:
            selected = [SAMPLE_3_VALIDATION]
    else:
        selected = list(ALL_SAMPLES)

    models = load_models_lock(_REPO_ROOT / "models.lock")
    prompts = load_prompts_lock(_REPO_ROOT / "prompts.lock")
    try:
        assert_freeze_consistent(models, prompts)
    except Exception as exc:  # noqa: BLE001
        st.error(f"Freeze mismatch: {exc}")
        st.stop()

    judge_model_id = st.selectbox(
        "Judge model",
        options=[p.model_id for p in models.providers],
        index=0,
    )
    judge_spec = models.get_model(judge_model_id)

    st.divider()
    st.subheader("Run output")
    run_id = st.text_input(
        "Run ID",
        value="ui-" + str(int(st.session_state.get("ui_run_counter", 0))),
        help="Subdirectory under results/ where artefacts are written.",
    )

# -----------------------------------------------------------------------------
# Main — run button
# -----------------------------------------------------------------------------

run_btn = st.button(
    "📊 Build verdict matrix",
    type="primary",
    use_container_width=True,
)

if run_btn:
    out_dir = _REPO_ROOT / "results" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    sast_dir = out_dir / "sast"
    sast_dir.mkdir(exist_ok=True)
    judge_dir = out_dir / "judge"
    judge_dir.mkdir(exist_ok=True)
    bench_dir = out_dir / "benchmark"
    bench_dir.mkdir(exist_ok=True)

    from common.hashing import sha256_str
    from common.schema import CrossModelOutput

    sast_results = {}
    judge_verdicts = {}
    benchmark_outputs = []

    progress = st.progress(0, text="Starting…")
    n = len(selected)

    for i, sample in enumerate(selected):
        # 1. SAST
        progress.progress((i + 0.1) / n, text=f"[{sample.prompt_id}] SAST…")
        sast = run_sast(sample.prompt_id, sample.expected_source)
        sast_results[sample.prompt_id] = sast
        (sast_dir / f"{sample.prompt_id}.json").write_text(
            json.dumps(sast.model_dump(mode="json"), indent=2)
        )

        # 2. Judge (stub mode — deterministic for the UI)
        progress.progress((i + 0.4) / n, text=f"[{sample.prompt_id}] Judge (stub)…")
        if 'f"SELECT' in sample.expected_source or 'password = "' in sample.expected_source:
            stub_json = (
                '{"verdict":"defect","cwe":"CWE-89","severity":"high",'
                '"confidence":0.85,"evidence":"SQL injection or hardcoded password detected"}'
            )
        elif 'int(' in sample.expected_source and 'age' in sample.expected_source:
            stub_json = (
                '{"verdict":"defect","cwe":"CWE-20","severity":"medium",'
                '"confidence":0.75,"evidence":"Missing input validation on age_str"}'
            )
        else:
            stub_json = (
                '{"verdict":"no-defect","cwe":null,"severity":null,'
                '"confidence":0.6,"evidence":"No defect pattern detected"}'
            )
        from common.schema import JudgeVerdict
        parsed = parse_response(stub_json)
        verdict = JudgeVerdict(
            prompt_id=sample.prompt_id,
            source_sha256=sha256_str(sample.expected_source),
            label=JudgeLabel(parsed["verdict"]),
            cwe=parsed["cwe"],
            severity=Severity(parsed["severity"]) if parsed["severity"] else None,
            confidence=parsed["confidence"],
            evidence=parsed["evidence"],
            provider=judge_spec.provider,
            model_id=judge_model_id,
            freeze_tag=models.freeze_tag,
        )
        judge_verdicts[sample.prompt_id] = verdict

        # 3. Benchmark (stub mode)
        progress.progress((i + 0.7) / n, text=f"[{sample.prompt_id}] Benchmark (stub)…")
        for spec in models.providers:
            benchmark_outputs.append(
                CrossModelOutput(
                    prompt_id=sample.prompt_id,
                    provider=spec.provider,
                    model_id=spec.model_id,
                    language=sample.language,
                    generated_source=sample.expected_source,
                    completion_metadata={"stub": True, "latency_ms": 0},
                    freeze_tag=models.freeze_tag,
                )
            )

        progress.progress((i + 1.0) / n, text=f"[{sample.prompt_id}] Done")

    benchmark_outputs = normalise_batch(benchmark_outputs)

    # 4. Build verdict matrix
    progress.progress(1.0, text="Building verdict matrix…")
    prompts_dicts = [
        {"prompt_id": s.prompt_id, "language": s.language, "task": s.task, "prompt_text": s.prompt_text}
        for s in selected
    ]
    matrix = build_verdict_matrix(
        prompts_dicts,
        sast_results=sast_results,
        judge_verdicts=judge_verdicts,
        cross_model_outputs=benchmark_outputs,
        freeze_tag=models.freeze_tag,
    )

    # Persist
    summary = summarise(matrix)
    residuals = residual_cwes(matrix)
    export_csv(matrix, out_dir / "verdict_matrix.csv")
    export_json(matrix, out_dir / "verdict_matrix.json", summary=summary, residual=residuals)
    render_dashboard(matrix, out_dir / "dashboard.html")
    queue = route_incomplete_rows(matrix, out_path=out_dir / "human_review_queue.json")

    st.session_state["matrix_run_dir"] = str(out_dir)
    st.session_state["matrix_run_id"] = run_id
    st.session_state["matrix_summary"] = summary
    st.session_state["matrix_residuals"] = residuals
    st.session_state["matrix_rows"] = [row.model_dump(mode="json") for row in matrix]
    st.session_state["matrix_queue"] = queue

# -----------------------------------------------------------------------------
# Display
# -----------------------------------------------------------------------------

run_dir = st.session_state.get("matrix_run_dir")
if run_dir is None:
    st.info("Pick a sample scope on the left, then click **Build verdict matrix**.")
    st.stop()

assert run_dir is not None  # type narrowing for LSP

st.divider()
st.success(f"✅ Run saved to `{run_dir}`")

run_id = st.session_state.get("matrix_run_id", "—")
summary = st.session_state.get("matrix_summary", {})
residuals = st.session_state.get("matrix_residuals", {})
rows = st.session_state.get("matrix_rows", [])
queue = st.session_state.get("matrix_queue", [])

st.subheader(f"Run `{run_id}` summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total rows", len(rows))
c2.metric("Concurrence", summary.get("concurrence", 0))
c3.metric("Partial", summary.get("partial_concurrence", 0))
c4.metric("Divergence / Incomplete", summary.get("divergence", 0) + summary.get("incomplete", 0))

if residuals:
    st.subheader("Residual CWEs (Judge-flagged but no SAST coverage)")
    st.json(residuals)

st.divider()
st.subheader("Verdict matrix rows")
st.dataframe(rows, use_container_width=True, hide_index=True)

if queue:
    st.divider()
    st.warning(f"⚠️ {len(queue)} row(s) flagged for human review")
    st.dataframe(queue, use_container_width=True, hide_index=True)

st.divider()
st.subheader("Artefacts")
st.code(
    f"""
{run_dir}/
├── sast/                       # Per-prompt Bandit + Semgrep findings
├── judge/                      # Stub verdicts (no audit.jsonl in UI mode)
├── benchmark/                  # Cross-model outputs (stub)
├── verdict_matrix.csv          # Per-prompt verdict table
├── verdict_matrix.json         # Same + summary + residuals
├── dashboard.html              # Stakeholder-facing dashboard
└── human_review_queue.json     # Incomplete / divergence rows
    """.strip(),
    language="text",
)

# Provide download links
csv_path = Path(run_dir) / "verdict_matrix.csv"
json_path = Path(run_dir) / "verdict_matrix.json"
dash_path = Path(run_dir) / "dashboard.html"
if csv_path.exists():
    with open(csv_path, "rb") as f:
        st.download_button(
            "⬇️ Download verdict_matrix.csv",
            data=f.read(),
            file_name=csv_path.name,
            mime="text/csv",
        )
if json_path.exists():
    with open(json_path, "rb") as f:
        st.download_button(
            "⬇️ Download verdict_matrix.json",
            data=f.read(),
            file_name=json_path.name,
            mime="application/json",
        )
if dash_path.exists():
    with open(dash_path, "rb") as f:
        st.download_button(
            "⬇️ Download dashboard.html",
            data=f.read(),
            file_name=dash_path.name,
            mime="text/html",
        )

st.caption("Next step: verify the SHA-256 manifest on the **Manifest** page.")
