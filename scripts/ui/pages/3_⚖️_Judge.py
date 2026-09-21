"""Streamlit page — ⚖️ Judge pipeline (LLM-as-Judge).

Lets the user pick a source + SAST findings, choose between the
deterministic stub mode (for offline testing) and the live LiteLLM
mode, and inspect the Judge verdict with bias controls.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from common.fixtures import SAMPLE_1_SQLI, SAMPLE_2_HARDCODED, SAMPLE_3_VALIDATION
from common.config import load_models_lock, load_prompts_lock, assert_freeze_consistent
from common.schema import JudgeLabel, Severity
from judge.audit_log import AuditLog
from judge.orchestrator import judge as judge_call
from judge.prompt_template import parse_response
from sast.runner import run_sast

st.set_page_config(page_title="Judge pipeline", page_icon="⚖️", layout="wide")

st.title("⚖️ Judge pipeline (LLM-as-Judge)")
st.markdown(
    """
    Invoke the Judge (§B.2) against a source + the SAST findings from the
    previous page. The Judge returns a constrained verdict:
    `defect` / `no-defect` / `inconclusive`, with CWE, severity, confidence,
    and free-text evidence. All calls are appended to the audit log
    (§B.4) — see the audit row at the bottom of the page.
    """
)

st.divider()

# -----------------------------------------------------------------------------
# Sidebar — mode + model picker
# -----------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Judge configuration")

    mode = st.radio(
        "Mode",
        options=["stub (offline, deterministic)", "live (LiteLLM call)"],
        index=0,
        help="Stub uses a deterministic heuristic (per §B.2 — for offline "
             "CI / testing). Live mode calls the actual Judge model via "
             "LiteLLM and requires API keys in env.",
    )

    models = load_models_lock(_REPO_ROOT / "models.lock")
    prompts = load_prompts_lock(_REPO_ROOT / "prompts.lock")
    try:
        assert_freeze_consistent(models, prompts)
    except Exception as exc:  # noqa: BLE001
        st.error(f"Freeze mismatch: {exc}")
        st.stop()

    model_options = [p.model_id for p in models.providers]
    judge_model_id = st.selectbox(
        "Judge model",
        options=model_options,
        index=0,
        help="The model that *evaluates* the source. Must match an entry in models.lock.",
    )
    judge_spec = models.get_model(judge_model_id)

    st.divider()
    st.subheader("Source")
    source_choice = st.radio(
        "Pick a source",
        options=[
            "p001 — SQL injection (CWE-89)",
            "p002 — Hardcoded password (CWE-798)",
            "p003 — Missing validation (CWE-20)",
        ],
        index=0,
    )

# -----------------------------------------------------------------------------
# Main — sample selection + SAST findings propagation
# -----------------------------------------------------------------------------

if source_choice.startswith("p001"):
    sample = SAMPLE_1_SQLI
elif source_choice.startswith("p002"):
    sample = SAMPLE_2_HARDCODED
else:
    sample = SAMPLE_3_VALIDATION

source = sample.expected_source

# Run SAST on the sample (so the Judge has the findings to compare against)
with st.spinner("Running SAST on the sample to feed findings into the Judge…"):
    sast_result = run_sast(sample.prompt_id, source)

sast_flags = [
    {
        "tool": f.tool.value,
        "rule_id": f.rule_id,
        "line": f.line,
        "message": f.message,
        "cwe": f.cwe,
        "severity": f.severity.value,
    }
    for f in sast_result.merged_findings
]

left, right = st.columns([1, 1])
with left:
    st.subheader("Source under review")
    st.code(source, language="python")
    st.caption(
        f"Sample `{sample.prompt_id}` · expected CWE `{sample.expected_cwe}` "
        f"· expected severity `{sample.expected_severity}`"
    )
with right:
    st.subheader("SAST findings (input to Judge)")
    if sast_flags:
        st.dataframe(sast_flags, use_container_width=True, hide_index=True)
    else:
        st.success("No SAST findings — Judge overlay is load-bearing for this sample.")
        st.caption("This matches Sample 3 (CWE-20). The Judge must catch the defect alone.")

st.divider()

run_btn = st.button("⚖️ Run Judge", type="primary", use_container_width=True)

verdict = None
verdict_source: str | None = None

if run_btn:
    if mode.startswith("live"):
        # Real LiteLLM call
        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            audit_path = Path(tmp.name)
        audit_log = AuditLog(audit_path)
        try:
            verdict = judge_call(
                prompt_id=sample.prompt_id,
                source_code=source,
                sast_findings=sast_flags,
                source_model_id=judge_model_id,
                judge_provider_spec=judge_spec,
                freeze_tag=models.freeze_tag,
                audit_log=audit_log,
            )
        except Exception as exc:  # noqa: BLE001
            st.error(f"Live Judge call failed: {exc}")
            audit_log.close()
            st.stop()
        finally:
            audit_log.close()
        verdict_source = "live"
    else:
        # Deterministic stub (mirrors scripts/run_full_evaluation.py)
        if 'f"SELECT' in source or 'password = "' in source:
            stub_json = (
                '{"verdict":"defect","cwe":"CWE-89","severity":"high",'
                '"confidence":0.85,"evidence":"SQL injection or hardcoded password detected"}'
            )
        elif 'int(' in source and 'age' in source:
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
        from common.hashing import sha256_str
        parsed = parse_response(stub_json)
        verdict = JudgeVerdict(
            prompt_id=sample.prompt_id,
            source_sha256=sha256_str(source),
            label=JudgeLabel(parsed["verdict"]),
            cwe=parsed["cwe"],
            severity=Severity(parsed["severity"]) if parsed["severity"] else None,
            confidence=parsed["confidence"],
            evidence=parsed["evidence"],
            provider=judge_spec.provider,
            model_id=judge_model_id,
            freeze_tag=models.freeze_tag,
        )
        verdict_source = "stub"

    st.session_state["judge_verdict"] = verdict
    st.session_state["judge_source"] = verdict_source

verdict = st.session_state.get("judge_verdict")
verdict_source = st.session_state.get("judge_source", "stub")
if verdict is None:
    st.info("Click **Run Judge** to populate the verdict card.")
    st.stop()

# Type narrowing: verdict is JudgeVerdict here, not None
assert verdict is not None

st.divider()
st.subheader("Judge verdict")

# Verdict card with semantic colour-coding
verdict_color = {
    JudgeLabel.DEFECT: "🔴",
    JudgeLabel.NO_DEFECT: "🟢",
    JudgeLabel.INCONCLUSIVE: "🟡",
}.get(verdict.label, "⚪")

c1, c2, c3 = st.columns(3)
with c1:
    st.metric("Verdict", f"{verdict_color} {verdict.label.value}")
with c2:
    st.metric("Confidence", f"{verdict.confidence:.2f}")
with c3:
    if verdict.severity:
        st.metric("Severity", verdict.severity.value)
    else:
        st.metric("Severity", "—")

st.write(
    f"**CWE**: `{verdict.cwe or '—'}`\n\n"
    f"**Evidence**:\n\n> {verdict.evidence}\n\n"
    f"**Judge**: `{verdict.provider}/{verdict.model_id}`\n\n"
    f"**Source**: `{verdict_source}`"
)

# Expected vs actual comparison
expected = (
    f"{sample.expected_cwe} ({sample.expected_severity})"
    if sample.expected_cwe
    else "no-defect"
)
actual = f"{verdict.cwe or '—'} ({verdict.severity.value if verdict.severity else '—'})"

if verdict.cwe == sample.expected_cwe:
    match = "✅ MATCH"
elif verdict.cwe is None and sample.expected_cwe is None:
    match = "✅ MATCH (both no-defect)"
else:
    match = "⚠️ MISMATCH"

st.write(f"**Expected** (§5.6 Table 5.7): `{expected}`")
st.write(f"**Actual**: `{actual}` — {match}")

st.divider()
st.subheader("Bias controls (§B.2.3)")
st.markdown(
    """
    Three bias mitigations are applied to every Judge call:
    - **Position** — judge prompt lists findings in a randomised order.
    - **Verbosity** — Judge response is constrained to the schema
      (`verdict`, `cwe`, `severity`, `confidence`, `evidence`); no prose.
    - **Self-enhancement** — Judge never evaluates its own output. The
      `source_model_id` is passed as a blinding tag; the Judge prompt
      does not reveal which model produced the source.
    """
)

st.divider()
st.subheader("Audit log entry (§B.4)")
st.json({
    "prompt_id": verdict.prompt_id,
    "source_sha256": verdict.source_sha256[:16] + "…",
    "judge": f"{verdict.provider}/{verdict.model_id}",
    "freeze_tag": verdict.freeze_tag,
    "verdict": verdict.label.value,
    "cwe": verdict.cwe,
    "severity": verdict.severity.value if verdict.severity else None,
    "confidence": verdict.confidence,
    "evidence": verdict.evidence,
    "source": verdict_source,
})

st.caption(
    "Next step: run the **Benchmark** page to compare source generation "
    "across multiple LLMs."
)
