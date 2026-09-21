"""Streamlit page — 🚀 Cross-Model Benchmarker.

Lets the user pick one of the 3 illustrative samples, choose which
models to benchmark, and dispatch parallel calls (or run stub mode
for offline testing). Shows the generated source side-by-side for
each provider and annotates with `static_label` from the normaliser.
"""
from __future__ import annotations

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
from common.fixtures import SAMPLE_1_SQLI, SAMPLE_2_HARDCODED, SAMPLE_3_VALIDATION
from common.hashing import sha256_str
from common.schema import CrossModelOutput
from benchmark.dispatcher import dispatch as benchmark_dispatch
from benchmark.normaliser import normalise_batch

st.set_page_config(page_title="Cross-Model Benchmarker", page_icon="🚀", layout="wide")

st.title("🚀 Cross-Model Benchmarker")
st.markdown(
    """
    Dispatch the same prompt to multiple LLM providers in parallel (§B.3).
    Each output is normalised with `static_label` (regex-based
    vulnerability classifier from `benchmark.normaliser`) for
    cross-model comparison (§5.5).
    """
)

st.divider()

# -----------------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Sample")
    sample_choice = st.radio(
        "Pick an illustrative sample",
        options=["p001 — SQLi", "p002 — Hardcoded pwd", "p003 — Missing validation"],
        index=0,
    )

    models = load_models_lock(_REPO_ROOT / "models.lock")
    prompts = load_prompts_lock(_REPO_ROOT / "prompts.lock")
    try:
        assert_freeze_consistent(models, prompts)
    except Exception as exc:  # noqa: BLE001
        st.error(f"Freeze mismatch: {exc}")
        st.stop()

    model_ids = st.multiselect(
        "Models to benchmark",
        options=[p.model_id for p in models.providers],
        default=[p.model_id for p in models.providers],
        help="Sub-select providers. Region-blocked providers are "
             "automatically skipped by the dispatcher (§5.5).",
    )

    mode = st.radio(
        "Mode",
        options=["stub (offline)", "live (parallel LLM calls)"],
        index=0,
        help="Stub mode uses the sample's expected_source as the generated "
             "output (deterministic, for testing). Live mode makes real "
             "parallel calls via ThreadPoolExecutor.",
    )

    max_workers = st.slider("Max parallel workers", min_value=1, max_value=8, value=4)

# -----------------------------------------------------------------------------
# Main — sample + dispatch
# -----------------------------------------------------------------------------

if sample_choice.startswith("p001"):
    sample = SAMPLE_1_SQLI
elif sample_choice.startswith("p002"):
    sample = SAMPLE_2_HARDCODED
else:
    sample = SAMPLE_3_VALIDATION

st.subheader("Prompt")
st.code(sample.prompt_text, language="text")
st.caption(
    f"Sample `{sample.prompt_id}` · language: `{sample.language}` · "
    f"expected source SHA-256 prefix: `{sample.sha256_prefix}`"
)

st.divider()

run_btn = st.button(
    "🚀 Dispatch",
    type="primary",
    use_container_width=True,
    disabled=not model_ids,
)

results: list[CrossModelOutput] | None = None
if run_btn:
    corpus_prompts = [
        {
            "prompt_id": sample.prompt_id,
            "prompt_text": sample.expected_source,
            "language": sample.language,
        }
    ]

    with st.spinner(f"Dispatching to {len(model_ids)} model(s)…"):
        if mode.startswith("stub"):
            # Build deterministic stubs (one per model)
            results = []
            for mid in model_ids:
                spec = models.get_model(mid)
                results.append(
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
        else:
            try:
                results = benchmark_dispatch(
                    corpus_prompts,
                    models_lock=models,
                    freeze_tag=models.freeze_tag,
                    model_ids=model_ids,
                    max_workers=max_workers,
                )
            except Exception as exc:  # noqa: BLE001
                st.error(f"Dispatch failed: {exc}")
                st.stop()

    # Annotate with static_label
    if results is not None:
        results = normalise_batch(results)
        st.session_state["benchmark_results"] = results

results = st.session_state.get("benchmark_results")
if not results:
    st.info("Click **Dispatch** to benchmark across the selected models.")
    st.stop()

assert results is not None

# -----------------------------------------------------------------------------
# Side-by-side output table
# -----------------------------------------------------------------------------

st.divider()
st.subheader(f"Results · {len(results)} output(s)")

rows = []
for r in results:
    # Pull static_label from metadata if present
    static_label = (r.completion_metadata or {}).get("static_label", "—")
    src_hash = sha256_str(r.generated_source)[:12]
    rows.append({
        "provider": r.provider,
        "model_id": r.model_id,
        "language": r.language,
        "static_label": static_label,
        "source_sha256": src_hash + "…",
        "latency_ms": r.latency_ms or "—",
    })
st.dataframe(rows, use_container_width=True, hide_index=True)

st.divider()
st.subheader("Generated source per model")

for r in results:
    region_note = ""
    spec = next((p for p in models.providers if p.model_id == r.model_id), None)
    if spec and spec.is_region_blocked:
        region_note = " · ⚠️ region-blocked (likely failed silently)"
    elif spec and spec.is_locally_served:
        region_note = " · 🏠 local"
    with st.expander(f"`{r.provider}/{r.model_id}`{region_note}", expanded=False):
        st.code(r.generated_source, language=r.language)
        src_hash = sha256_str(r.generated_source)[:12]
        st.caption(f"freeze_tag: `{r.freeze_tag}` · SHA-256 prefix: `{src_hash}…`")
        if r.completion_metadata:
            st.json(r.completion_metadata)

st.divider()
st.subheader("Cross-model convergence (per §5.5)")
# Count distinct static_labels
labels = [(r.completion_metadata or {}).get("static_label", "—") for r in results]
unique_labels = set(labels)
if len(unique_labels) == 1 and "—" not in unique_labels:
    st.success(
        f"✅ All {len(results)} models converged on the same static_label: "
        f"`{next(iter(unique_labels))}`. This is the concurrence class."
    )
elif "—" in unique_labels:
    st.warning(
        "Some outputs lack a static_label annotation (live mode without the normaliser). "
        "Run a full evaluation to get proper labels."
    )
else:
    sorted_labels = sorted(l for l in unique_labels if isinstance(l, str))
    st.info(
        f"Models diverged across {len(sorted_labels)} static_labels: "
        f"{sorted_labels}. This is the divergence class (§5.5)."
    )

st.caption(
    "Next step: build a verdict matrix from these outputs on the "
    "**Verdict Matrix** page."
)
