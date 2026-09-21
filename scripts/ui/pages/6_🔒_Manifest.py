"""Streamlit page — 🔒 Manifest (SHA-256 sealing).

Implements the §3.7 / §B.6.4 sealing commitment. Computes SHA-256
over every artefact in a run directory, verifies against an existing
manifest (if present), and produces a tamper-detection report.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from common.hashing import sha256_file, sha256_str

st.set_page_config(page_title="Manifest", page_icon="🔒", layout="wide")

st.title("🔒 Manifest — SHA-256 sealing")
st.markdown(
    """
    Per **§3.7 / §B.6.4**, every evaluation run must end with a
    `manifest.sha256` file that seals the input corpus, per-pipeline
    results, and verdict matrix into a single hash chain. Any
    post-hoc modification of those files is detectable on the next
    re-execution.
    """
)

st.divider()

# -----------------------------------------------------------------------------
# Sidebar — run picker
# -----------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Run directory")
    results_root = _REPO_ROOT / "results"
    if not results_root.exists():
        st.error("No results/ directory yet.")
        st.stop()

    runs = sorted([p for p in results_root.iterdir() if p.is_dir()])
    if not runs:
        st.warning("No runs yet. Build one on the **Verdict Matrix** page first.")
        st.stop()

    run_names = [p.name for p in runs]
    selected_run = st.selectbox("Pick a run", options=run_names, index=len(run_names) - 1)
    run_dir = results_root / selected_run

# -----------------------------------------------------------------------------
# Main — list artefacts + compute/verify manifest
# -----------------------------------------------------------------------------

st.subheader(f"Run `{selected_run}`")

artefact_paths = []
for rel in [
    "verdict_matrix.csv",
    "verdict_matrix.json",
    "dashboard.html",
    "human_review_queue.json",
    "judge/bias_summary.json",
    "judge/audit.jsonl",
]:
    p = run_dir / rel
    if p.exists():
        artefact_paths.append(p)
for sub in ("sast", "benchmark"):
    d = run_dir / sub
    if d.exists():
        for p in sorted(d.glob("*.json")):
            artefact_paths.append(p)

if not artefact_paths:
    st.warning(f"No artefacts found in `{run_dir}`.")
    st.stop()

st.write(f"**{len(artefact_paths)}** artefact(s) found")

action = st.radio(
    "Action",
    options=["Generate manifest (writes manifest.sha256)", "Verify existing manifest (read-only)"],
    index=1,
)

if action.startswith("Generate"):
    if st.button("🔒 Generate manifest.sha256", type="primary"):
        lines = []
        for p in artefact_paths:
            rel = p.relative_to(run_dir)
            digest = sha256_file(p)
            lines.append(f"{digest}  {rel}")
        body = "\n".join(lines) + "\n"
        seal = sha256_str(body)
        final = f"{seal}  manifest.sha256\n{body}"
        out_path = run_dir / "manifest.sha256"
        out_path.write_text(final)
        st.success(f"✅ Wrote `{out_path}` (seal: `{seal[:16]}…`)")
        st.session_state["manifest_seal"] = seal
else:
    manifest_path = run_dir / "manifest.sha256"
    if not manifest_path.exists():
        st.warning(
            f"No existing `manifest.sha256` in `{run_dir}`. "
            f"Switch to **Generate** above to create one."
        )
        st.stop()

    # Verify
    raw = manifest_path.read_text().splitlines()
    # First line is the self-seal
    recorded_seal = raw[0].split("  ")[0]
    recorded_lines = raw[1:]

    actual_lines = []
    mismatches = []
    for p in artefact_paths:
        rel = str(p.relative_to(run_dir))
        actual_digest = sha256_file(p)
        actual_lines.append(f"{actual_digest}  {rel}")

        # Find matching recorded entry
        recorded = next((l for l in recorded_lines if l.endswith(f"  {rel}")), None)
        if recorded is None:
            mismatches.append({"file": rel, "issue": "missing from manifest"})
        elif recorded.split("  ")[0] != actual_digest:
            mismatches.append({
                "file": rel,
                "issue": f"hash mismatch (recorded `{recorded.split('  ')[0][:16]}…`, actual `{actual_digest[:16]}…`)",
            })

    # Recompute self-seal
    body = "\n".join(actual_lines) + "\n"
    recomputed_seal = sha256_str(body)

    st.subheader("Verification")
    if not mismatches and recomputed_seal == recorded_seal:
        st.success(
            f"✅ Manifest verified. Seal `{recorded_seal[:16]}…` matches "
            f"recomputed seal. All {len(artefact_paths)} artefact(s) intact."
        )
    else:
        st.error("❌ Manifest mismatch — run has been modified since sealing!")
        if recomputed_seal != recorded_seal:
            st.write(
                f"  - Self-seal mismatch: recorded `{recorded_seal[:16]}…`, "
                f"recomputed `{recomputed_seal[:16]}…`"
            )
        if mismatches:
            st.dataframe(mismatches, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Recorded manifest")
    st.code(
        manifest_path.read_text(),
        language="text",
    )

st.divider()
st.subheader("Artefacts under seal")
rows = []
for p in artefact_paths:
    rel = str(p.relative_to(run_dir))
    digest = sha256_file(p)
    rows.append({
        "file": rel,
        "size": p.stat().st_size,
        "sha256": digest[:16] + "…",
    })
st.dataframe(rows, use_container_width=True, hide_index=True)

st.caption("Next step: run the **Tests** page to confirm the pytest suite still passes.")
