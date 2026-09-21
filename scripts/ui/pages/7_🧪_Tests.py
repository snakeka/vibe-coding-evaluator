"""Streamlit page — 🧪 Tests (pytest runner).

Run the project test suite from the UI with live log streaming.
Supports filtering by marker (unit / integration / live) and shows
the pass/fail summary plus any failure output.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

import streamlit as st

st.set_page_config(page_title="Tests", page_icon="🧪", layout="wide")

st.title("🧪 Test runner")
st.markdown(
    """
    Run the project's pytest suite from the browser. Use the marker
    filter to narrow the run:
    - **unit** — pure unit tests, no external deps
    - **integration** — requires bandit / semgrep on PATH
    - **live** — requires API keys for real LLM calls
    """
)

st.divider()

# -----------------------------------------------------------------------------
# Sidebar — marker filter
# -----------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Marker filter")
    marker = st.radio(
        "Markers",
        options=["all", "unit only", "integration only", "live only"],
        index=0,
        help="Filter by pytest marker (see pyproject.toml).",
    )

    extra = st.text_input(
        "Extra pytest args",
        value="",
        placeholder="e.g. -k 'test_run_sast'",
        help="Passed through to pytest after `-m MARKER`.",
    )

    verbose = st.checkbox("Verbose output (-v)", value=True)

# -----------------------------------------------------------------------------
# Build command
# -----------------------------------------------------------------------------

mark_arg = {
    "all": "",
    "unit only": "-m unit",
    "integration only": "-m integration",
    "live only": "-m live",
}[marker]

cmd = [sys.executable, "-m", "pytest"]
if mark_arg:
    cmd.extend(mark_arg.split())
if verbose:
    cmd.append("-v")
if extra.strip():
    cmd.extend(extra.strip().split())
cmd.append("--tb=short")

st.code(" ".join(cmd), language="bash")

st.divider()

run_btn = st.button("🧪 Run pytest", type="primary", use_container_width=True)
exit_code: int | None = None
log: str | None = None

if run_btn:
    log_placeholder = st.empty()
    log_buffer = ""
    proc = None

    with st.spinner("Running pytest…"):
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(_REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:  # noqa: BLE001
            st.error(f"Failed to start pytest: {exc}")
            st.stop()

        # Stream output line by line
        if proc is not None and proc.stdout is not None:
            for line in proc.stdout:
                log_buffer += line
                log_placeholder.code(log_buffer, language="bash")

        if proc is not None:
            proc.wait()
            exit_code = proc.returncode

    st.session_state["test_exit_code"] = exit_code
    st.session_state["test_log"] = log_buffer
    log = log_buffer

# -----------------------------------------------------------------------------
# Display results
# -----------------------------------------------------------------------------

log = st.session_state.get("test_log")
exit_code = st.session_state.get("test_exit_code")

if log is None:
    st.info("Click **Run pytest** to start.")
    st.stop()

st.divider()
st.subheader("Results")
if exit_code == 0:
    st.success(f"✅ pytest exited with code 0 (all tests passed)")
else:
    st.error(f"❌ pytest exited with code {exit_code}")

st.subheader("Full log")
st.code(log, language="bash")

# Try to extract a pass/fail summary from the log
import re

if log is not None:
    summary_match = re.search(r"=+ (\d+ passed.*?) =+", log)
    if summary_match:
        st.caption(f"Summary: {summary_match.group(1)}")

st.caption("All UI pages now share state — return to Home for an overview.")
