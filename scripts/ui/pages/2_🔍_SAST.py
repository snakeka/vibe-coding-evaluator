"""Streamlit page — 🔍 SAST pipeline (Bandit + Semgrep).

Lets the user pick a source file (one of the 3 illustrative samples or
upload their own .py file), run the SAST pipeline, and inspect the
merged findings table with severity / CWE / line annotations.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from common.fixtures import ALL_SAMPLES, SAMPLE_1_SQLI, SAMPLE_2_HARDCODED, SAMPLE_3_VALIDATION
from common.schema import SastTool
from sast.runner import _bandit_on_path, _semgrep_on_path, run_sast

st.set_page_config(page_title="SAST pipeline", page_icon="🔍", layout="wide")

st.title("🔍 SAST pipeline")
st.markdown(
    """
    Run the SAST pipeline (§B.1) against an illustrative sample or any
    uploaded Python file. The pipeline runs **Bandit** and **Semgrep**
    in parallel, then deduplicates overlapping findings via
    `sast.merger.merge_findings`.
    """
)

st.divider()

# -----------------------------------------------------------------------------
# Sidebar — tool availability + source picker
# -----------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Tool availability")
    bandit_ok = _bandit_on_path()
    semgrep_ok = _semgrep_on_path()
    st.write(f"Bandit:  {'✅' if bandit_ok else '❌ not on PATH'}")
    st.write(f"Semgrep: {'✅' if semgrep_ok else '❌ not on PATH'}")
    if not (bandit_ok and semgrep_ok):
        st.warning(
            "One or both SAST tools are missing. Install with:\n\n"
            "```\npip install -e '.[sast]'\n"
            "# bandit + semgrep are CLI tools — install via pipx or brew:\n"
            "pipx install bandit semgrep\n```"
        )

    st.divider()
    st.subheader("Pick a source")
    source_choice = st.radio(
        "Illustrative sample",
        options=[
            "p001 — SQL injection (CWE-89)",
            "p002 — Hardcoded password (CWE-798)",
            "p003 — Missing validation (CWE-20)",
            "Upload my own .py",
        ],
        index=0,
    )

uploaded_source = None
if source_choice == "Upload my own .py":
    uploaded = st.file_uploader("Upload a Python file", type=["py"])
    if uploaded is not None:
        uploaded_source = uploaded.read().decode("utf-8")

if source_choice.startswith("p001"):
    source = SAMPLE_1_SQLI.expected_source
    sample_meta = SAMPLE_1_SQLI
elif source_choice.startswith("p002"):
    source = SAMPLE_2_HARDCODED.expected_source
    sample_meta = SAMPLE_2_HARDCODED
elif source_choice.startswith("p003"):
    source = SAMPLE_3_VALIDATION.expected_source
    sample_meta = SAMPLE_3_VALIDATION
elif uploaded_source is not None:
    source = uploaded_source
    sample_meta = None
else:
    source = None
    sample_meta = None

# -----------------------------------------------------------------------------
# Main — source preview + run button + findings table
# -----------------------------------------------------------------------------

if source is None:
    st.info("Pick a source on the left sidebar, or upload a .py file.")
    st.stop()

# Type narrowing: source is str here, not None
assert source is not None

left, right = st.columns([1, 1])
with left:
    st.subheader("Source under analysis")
    st.code(source, language="python")
    if sample_meta is not None:
        st.caption(
            f"Sample `{sample_meta.prompt_id}` · expected CWE `{sample_meta.expected_cwe}` · "
            f"expected severity `{sample_meta.expected_severity}` · "
            f"expected triangulation `{sample_meta.expected_triangulation}`"
        )

with right:
    st.subheader("Expected defect (per §5.6 Table 5.7)")
    if sample_meta is not None:
        st.write(
            f"- **CWE**: `{sample_meta.expected_cwe}`\n"
            f"- **Severity**: `{sample_meta.expected_severity}`\n"
            f"- **SAST predicted**: `{', '.join(sample_meta.sast_predicted) or '(none — Judge overlay load-bearing)'}`\n"
            f"- **Triangulation**: `{sample_meta.expected_triangulation}`"
        )
    else:
        st.write("Custom upload — no expected defect registered.")

st.divider()

run_btn = st.button("🚀 Run SAST", type="primary", use_container_width=True)

if run_btn:
    with st.spinner("Running Bandit + Semgrep in parallel…"):
        try:
            prompt_id = sample_meta.prompt_id if sample_meta else "user-upload"
            result = run_sast(prompt_id, source, path=f"<ui:{prompt_id}>")
            st.session_state["sast_result"] = result
            st.session_state["sast_source"] = source
        except Exception as exc:  # noqa: BLE001
            st.error(f"SAST pipeline crashed: {exc}")
            st.stop()

result = st.session_state.get("sast_result")
if result is None:
    st.info("Click **Run SAST** to populate the findings table.")
    st.stop()

# Type narrowing: result is SastResult here, not None
assert result is not None

st.divider()
st.subheader("Results")

# -----------------------------------------------------------------------------
# Summary metrics
# -----------------------------------------------------------------------------

findings = result.merged_findings
n_total = len(findings)
n_bandit_only = sum(1 for f in findings if f.tool == SastTool.BANDIT)
n_semgrep_only = sum(1 for f in findings if f.tool == SastTool.SEMGREP)
n_both = sum(
    1
    for f in findings
    if any(b.line == f.line and b.rule_id == f.rule_id for b in result.bandit_findings)
    and any(s.line == f.line and s.rule_id == f.rule_id for s in result.semgrep_findings)
)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total findings", n_total)
c2.metric("Bandit-only", n_bandit_only)
c3.metric("Semgrep-only", n_semgrep_only)
c4.metric("Bandit ∩ Semgrep", n_both)

# -----------------------------------------------------------------------------
# Findings table
# -----------------------------------------------------------------------------

if not findings:
    st.success("✅ No defects detected by Bandit or Semgrep.")
    st.caption(
        "This matches Sample 3 (CWE-20) where neither tool detects — the Judge "
        "overlay becomes load-bearing (see the **Judge** page next)."
    )
else:
    rows = []
    for f in findings:
        rows.append({
            "tool": f.tool.value,
            "rule_id": f.rule_id,
            "line": f.line,
            "severity": f.severity.value,
            "CWE": f.cwe or "—",
            "message": f.message,
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

st.divider()
st.subheader("Pipeline metadata")
st.json({
    "prompt_id": result.prompt_id,
    "source_sha256": result.source_sha256[:16] + "…",
    "elapsed_ms": result.elapsed_ms,
    "bandit_exit_code": result.band_exit_code,
    "semgrep_exit_code": result.semgrep_exit_code,
    "bandit_findings": len(result.bandit_findings),
    "semgrep_findings": len(result.semgrep_findings),
})

st.caption("Next step: take these findings to the **Judge** page to see how the LLM-as-Judge layer rates them.")
