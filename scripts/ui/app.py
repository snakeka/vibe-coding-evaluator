"""scripts/ui/app.py — Streamlit UI for the vibe-coding-evaluator artefact.

A multi-page Streamlit app that exposes the four dissertation pipelines
(SAST / Judge / Benchmark / Report) plus run history and test runner.

Run:
    streamlit run scripts/ui/app.py

The UI reuses the existing CLI pipeline code under scripts/, sast/, judge/,
benchmark/, and report/. No pipeline logic is duplicated here — only the
frontend.

§5.5 transparency: the UI shows the same controls (model picker, mode toggle,
freeze tag) that the CLI exposes, so reviewers can reproduce §5.6 Table 5.7
interactively rather than reading the static table in the dissertation.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running as `streamlit run scripts/ui/app.py` from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from common.config import (
    assert_freeze_consistent,
    load_env,
    load_models_lock,
    load_prompts_lock,
)


# -----------------------------------------------------------------------------
# Page config
# -----------------------------------------------------------------------------

st.set_page_config(
    page_title="vibe-coding-evaluator",
    page_icon="🧪",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "About": (
            "Web UI for the MSc dissertation artefact 'Evaluating Vibe Coding'. "
            "See §4.5 (architecture) and §5.6 Table 5.7 (results)."
        ),
        "Get Help": "https://github.com/snakeka/vibe-coding-evaluator",
    },
)


# -----------------------------------------------------------------------------
# Sidebar — repo status / freeze tag / model picker (shared across all pages)
# -----------------------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def _load_freeze():
    """Load models.lock + prompts.lock (cached for the lifetime of the session)."""
    load_env()
    models = load_models_lock(_REPO_ROOT / "models.lock")
    prompts = load_prompts_lock(_REPO_ROOT / "prompts.lock")
    try:
        assert_freeze_consistent(models, prompts)
        freeze_status = "✅ Consistent"
    except Exception as exc:  # noqa: BLE001
        freeze_status = f"❌ {exc}"
    return models, prompts, freeze_status


with st.sidebar:
    st.title("🧪 vibe-coding-evaluator")
    st.caption("MSc dissertation artefact · University of Liverpool CSCK700")

    models, prompts, freeze_status = _load_freeze()

    st.divider()
    st.subheader("§3.5 Freeze status")
    st.write(f"**freeze_tag**: `{models.freeze_tag}`")
    st.write(f"**status**: {freeze_status}")
    st.write(f"**models**: {len(models.providers)} providers")
    st.write(f"**prompts**: {len(prompts.prompts)} locked")

    st.divider()
    st.subheader("Navigation")
    st.page_link("app.py", label="🏠 Home", icon="🏠")
    st.page_link("pages/2_🔍_SAST.py", label="🔍 SAST pipeline", icon="🔍")
    st.page_link("pages/3_⚖️_Judge.py", label="⚖️ Judge pipeline", icon="⚖️")
    st.page_link("pages/4_🚀_Benchmark.py", label="🚀 Benchmark", icon="🚀")
    st.page_link("pages/5_📊_Verdict_Matrix.py", label="📊 Verdict matrix", icon="📊")
    st.page_link("pages/6_🔒_Manifest.py", label="🔒 Manifest", icon="🔒")
    st.page_link("pages/7_🧪_Tests.py", label="🧪 Tests", icon="🧪")

    st.divider()
    with st.expander("Pipeline models (from models.lock)", expanded=False):
        for spec in models.providers:
            region = ""
            if spec.is_region_blocked:
                region = " ⚠️ region-blocked"
            elif spec.is_locally_served:
                region = " 🏠 local"
            st.write(
                f"**{spec.provider}/{spec.model_id}**{region}\n\n"
                f"endpoint: `{spec.endpoint or '(default)'}`\n\n"
                f"locked_at: `{spec.locked_at}`"
            )


# -----------------------------------------------------------------------------
# Home page content
# -----------------------------------------------------------------------------

st.title("🧪 vibe-coding-evaluator")
st.markdown(
    """
    **Design-science framework for validating LLM-generated code.**

    This is the web UI for the dissertation artefact described in
    *Chapter 4* of the MSc dissertation *Evaluating Vibe Coding*.
    The four pipelines — **SAST**, **Judge**, **Benchmark**, **Report** —
    are exposed as interactive pages on the left.

    All controls here mirror the CLI flags in
    `scripts/run_full_evaluation.py`, so the same §5.6 Table 5.7
    results can be reproduced interactively without re-reading the
    static dissertation table.
    """
)

st.divider()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric(
        "Freeze tag",
        models.freeze_tag,
        help="Per §3.5. Bumping this requires a documented justification (§3.7).",
    )
with col2:
    st.metric(
        "Models",
        len(models.providers),
        help="Providers in models.lock (one may be region-blocked).",
    )
with col3:
    st.metric(
        "Prompts",
        len(prompts.prompts),
        help="Prompts in prompts.lock (sha256-sealed).",
    )
with col4:
    st.metric(
        "Freeze status",
        "OK" if freeze_status.startswith("✅") else "FAIL",
        delta=None,
        delta_color="off",
    )

st.divider()

st.subheader("Quick start")

st.markdown(
    """
    1. **SAST pipeline** → pick a corpus file → run SAST (Bandit + Semgrep)
       → review findings table.
    2. **Judge pipeline** → pick a source → toggle stub vs. live mode → see
       verdict (defect / no-defect) with evidence.
    3. **Benchmark** → pick a prompt + models → run parallel dispatch →
       compare generated source across providers.
    4. **Verdict matrix** → browse prior runs → open the dashboard.
    5. **Manifest** → verify SHA-256 sealing of any prior run.
    6. **Tests** → run pytest with live progress.
    """
)

st.subheader("Repository layout")

st.code(
    """
vibe-coding-evaluator/
├── sast/        # §4.5 — Bandit + Semgrep pipeline
├── judge/       # §4.5 — LiteLLM judge + bias controls
├── benchmark/   # §4.5 — Cross-model parallel dispatcher
├── report/      # §4.5 — Verdict matrix + dashboard
├── common/      # Freeze loader, schema, hashing
├── scripts/
│   ├── run_full_evaluation.py   # CLI entry (this UI wraps it)
│   └── ui/                      # ← this Streamlit app
├── corpus/      # §3.5 frozen input prompts
├── models.lock  # §B.6 provider / model / endpoint freeze
├── prompts.lock # §B.6 prompt hash freeze
└── manifest.sha256   # §B.6 per-run sealing artefact
    """.strip(),
    language="text",
)

st.subheader("Reproduction")

st.markdown(
    f"""
    ```bash
    git clone https://github.com/snakeka/vibe-coding-evaluator
    cd vibe-coding-evaluator
    pip install -e ".[dev]"
    streamlit run scripts/ui/app.py
    ```
    """
)

st.caption(f"Repo root: `{_REPO_ROOT}`")
