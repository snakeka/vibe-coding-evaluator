"""scripts.run_full_evaluation — end-to-end driver (§4.5 + §B.6).

Orchestrates the four pipelines in sequence:

1. SAST pipeline (Bandit + Semgrep) on every prompt's expected source
2. Judge pipeline (LiteLLM) on every prompt
3. Cross-Model Benchmarker on every prompt × every provider
4. Report Generator: verdict matrix → CSV + JSON + dashboard

The run output is written to ``results/<run-id>/`` with the
following layout:

    results/<run-id>/
        sast/
            <prompt_id>.json
        judge/
            audit.jsonl
            bias_summary.json
        benchmark/
            <prompt_id>__<model_id>.json
        verdict_matrix.csv
        verdict_matrix.json
        dashboard.html
        manifest.sha256        ← computed by scripts/generate_manifest.py

Usage
-----

    python scripts/run_full_evaluation.py \\
        --prompts prompts.lock \\
        --models models.lock \\
        --corpus corpus/illustrative \\
        --out results/run-$(date +%Y%m%d-%H%M%S) \\
        --judge-provider ollama \\
        --judge-model qwen2.5-coder:32b
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Allow running as `python scripts/run_full_evaluation.py` from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.config import (
    assert_freeze_consistent,
    load_env,
    load_models_lock,
    load_prompts_lock,
)
from common.fixtures import ALL_SAMPLES, sample_by_id
from common.hashing import sha256_file, sha256_str
from common.schema import CrossModelOutput, JudgeVerdict, SastResult
from benchmark.dispatcher import dispatch as benchmark_dispatch
from benchmark.normaliser import normalise_batch
from judge.audit_log import AuditLog
from judge.orchestrator import judge as judge_call
from report.divergence_router import route_incomplete_rows
from report.exporter import export_csv, export_json, render_dashboard
from report.verdict_merger import build_verdict_matrix, residual_cwes, summarise
from sast.runner import run_sast


# ---------------------------------------------------------------------------
# Per-pipeline runners — each writes its artefacts to the run directory
# ---------------------------------------------------------------------------


def run_sast_pipeline(
    prompts: list[dict],
    corpus_dir: Path,
    out_dir: Path,
) -> dict[str, SastResult]:
    """Run the SAST pipeline against each prompt's source file (§B.1)."""
    sast_dir = out_dir / "sast"
    sast_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, SastResult] = {}
    for p in prompts:
        prompt_id = p["prompt_id"]
        # The corpus file is named <prompt_id>.py
        src_path = corpus_dir / f"{prompt_id}.py"
        if not src_path.exists():
            print(f"  [SAST] {prompt_id}: source not found at {src_path}, skipping")
            continue
        source = src_path.read_text()
        result = run_sast(prompt_id, source, path=str(src_path))
        results[prompt_id] = result
        # Persist per-prompt result
        (sast_dir / f"{prompt_id}.json").write_text(
            json.dumps(result.model_dump(mode="json"), indent=2)
        )
        n_findings = len(result.merged_findings)
        print(f"  [SAST] {prompt_id}: {n_findings} findings ({result.elapsed_ms}ms)")

    return results


def run_judge_pipeline(
    prompts: list[dict],
    corpus_dir: Path,
    sast_results: dict[str, SastResult],
    judge_provider: str,
    judge_model_id: str,
    freeze_tag: str,
    out_dir: Path,
    models_lock,
    live: bool = False,
) -> dict[str, JudgeVerdict]:
    """Run the Judge pipeline (§B.2).

    Parameters
    ----------
    live : bool
        If True, call LiteLLM for real. If False, use a deterministic
        stub that parses the source code for obvious defect patterns.
        The stub is used for CI and for tests; the live mode is what
        the dissertation §5.4 will exercise on the user's Mac.
    """
    judge_dir = out_dir / "judge"
    judge_dir.mkdir(parents=True, exist_ok=True)
    audit_log = AuditLog(judge_dir / "audit.jsonl")

    judge_spec = models_lock.get_model(judge_model_id)
    if judge_spec.provider != judge_provider:
        raise ValueError(
            f"Judge provider '{judge_provider}' does not match "
            f"model '{judge_model_id}' (provider: '{judge_spec.provider}'). "
            f"Use --judge-model to specify a model with provider={judge_provider}."
        )

    results: dict[str, JudgeVerdict] = {}
    for p in prompts:
        prompt_id = p["prompt_id"]
        src_path = corpus_dir / f"{prompt_id}.py"
        if not src_path.exists():
            print(f"  [Judge] {prompt_id}: source not found, skipping")
            continue
        source = src_path.read_text()

        # Convert SastResult findings to the dict form the Judge expects
        sast = sast_results.get(prompt_id)
        sast_flags = []
        if sast:
            for f in sast.merged_findings:
                sast_flags.append({
                    "tool": f.tool.value,
                    "rule_id": f.rule_id,
                    "line": f.line,
                    "message": f.message,
                    "cwe": f.cwe,
                    "severity": f.severity.value,
                })

        if live:
            # Real LLM call via LiteLLM
            verdict = judge_call(
                prompt_id=prompt_id,
                source_code=source,
                sast_findings=sast_flags,
                source_model_id=judge_model_id,   # Judge evaluating model == judge_model
                judge_provider_spec=judge_spec,
                freeze_tag=freeze_tag,
                audit_log=audit_log,
            )
        else:
            # Stub: derive a deterministic verdict from the source content.
            # Used for offline / CI runs.
            from judge.prompt_template import parse_response
            from common.schema import JudgeLabel, Severity
            from judge.audit_log import make_audit_record
            import time as _time

            # Heuristic: if source contains known bad patterns, mark defect
            if 'f"SELECT' in source or "f'SELECT" in source or 'password = "' in source:
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
            parsed = parse_response(stub_json)
            t0 = _time.monotonic()
            verdict = JudgeVerdict(
                prompt_id=prompt_id,
                source_sha256=sha256_str(source),
                label=JudgeLabel(parsed["verdict"]),
                cwe=parsed["cwe"],
                severity=Severity(parsed["severity"]) if parsed["severity"] else None,
                confidence=parsed["confidence"],
                evidence=parsed["evidence"],
                provider=judge_provider,
                model_id=judge_model_id,
                freeze_tag=freeze_tag,
            )
            # Audit-log the stub call
            record = make_audit_record(
                caller="run_full_evaluation[stub]",
                prompt_id=prompt_id,
                freeze_tag=freeze_tag,
                provider=judge_provider,
                model_id=judge_model_id,
                seed=None,
                ordering_key=42,
                response=stub_json,
                prompt_text=f"[stub mode] {prompt_id}",
                leakage_strings=[judge_model_id],
                start_time=t0,
                metadata={"stub": True},
            )
            audit_log.write(record)

        results[prompt_id] = verdict
        print(
            f"  [Judge] {prompt_id}: {verdict.label.value}"
            f" ({verdict.cwe or 'no-cwe'}, conf={verdict.confidence:.2f})"
        )

    audit_log.close()
    return results


def run_benchmark_pipeline(
    prompts: list[dict],
    corpus_dir: Path,
    freeze_tag: str,
    out_dir: Path,
    models_lock,
    live: bool = False,
    max_workers: int = 4,
) -> list[CrossModelOutput]:
    """Run the Cross-Model Benchmarker (§B.3).

    Parameters
    ----------
    live : bool
        If True, dispatch real LLM calls. If False, use the expected
        source from the fixtures as a stub output.
    """
    bench_dir = out_dir / "benchmark"
    bench_dir.mkdir(parents=True, exist_ok=True)

    if live:
        # Build a list of {prompt_id, prompt_text, language} from the
        # corpus files; the prompt text is the source code itself
        # (so the LLM re-generates it).
        corpus_prompts: list[dict] = []
        for p in prompts:
            src = corpus_dir / f"{p['prompt_id']}.py"
            if src.exists():
                corpus_prompts.append({
                    "prompt_id": p["prompt_id"],
                    "prompt_text": src.read_text(),
                    "language": p.get("language", "python"),
                })
        results = benchmark_dispatch(
            corpus_prompts,
            models_lock=models_lock,
            freeze_tag=freeze_tag,
            max_workers=max_workers,
        )
    else:
        # Stub mode: use the corpus file as the "generated source" and
        # apply the static_label heuristic via the normaliser.
        results = []
        for p in prompts:
            src_path = corpus_dir / f"{p['prompt_id']}.py"
            if not src_path.exists():
                continue
            source = src_path.read_text()
            for spec in models_lock.providers:
                results.append(CrossModelOutput(
                    prompt_id=p["prompt_id"],
                    provider=spec.provider,
                    model_id=spec.model_id,
                    language=p.get("language", "python"),
                    generated_source=source,
                    completion_metadata={"stub": True, "latency_ms": 0},
                    freeze_tag=freeze_tag,
                ))

    # Annotate with static_label
    results = normalise_batch(results)

    # Persist per-(prompt, model) outputs
    for r in results:
        path = bench_dir / f"{r.prompt_id}__{r.model_id.replace('/', '_')}.json"
        path.write_text(json.dumps(r.model_dump(mode="json"), indent=2))

    print(f"  [Benchmark] {len(results)} outputs across {len(models_lock.providers)} providers")
    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a full vibe-coding evaluation.")
    parser.add_argument("--prompts", default="prompts.lock", help="Path to prompts.lock")
    parser.add_argument("--models", default="models.lock", help="Path to models.lock")
    parser.add_argument("--corpus", default="corpus/illustrative", help="Path to corpus dir")
    parser.add_argument("--out", required=True, help="Output run directory")
    parser.add_argument("--judge-provider", default="ollama", help="Judge provider")
    parser.add_argument("--judge-model", default="qwen2.5-coder:32b", help="Judge model_id")
    parser.add_argument(
        "--mode",
        choices=["stub", "live"],
        default="stub",
        help="stub: deterministic offline mode for CI/tests; live: real LLM calls",
    )
    parser.add_argument("--max-workers", type=int, default=4)
    args = parser.parse_args()

    load_env()

    # Load and validate freeze artefacts (§3.5)
    models = load_models_lock(args.models)
    prompts_lock = load_prompts_lock(args.prompts)
    assert_freeze_consistent(models, prompts_lock)
    freeze_tag = models.freeze_tag

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Convert prompts.lock entries to plain dicts
    prompts = [
        {
            "prompt_id": p.prompt_id,
            "language": p.language,
            "task": p.task,
            "prompt_text": p.prompt_text,
        }
        for p in prompts_lock.prompts
    ]

    print(f"=== vibe-coding-evaluator ===")
    print(f"freeze_tag: {freeze_tag}")
    print(f"models: {[p.model_id for p in models.providers]}")
    print(f"prompts: {len(prompts)}")
    print(f"mode: {args.mode}")
    print()

    t0 = time.monotonic()

    # 1. SAST pipeline
    print("[1/4] SAST pipeline")
    corpus_dir = Path(args.corpus)
    sast_results = run_sast_pipeline(prompts, corpus_dir, out_dir)
    print()

    # 2. Judge pipeline
    print("[2/4] Judge pipeline")
    judge_verdicts = run_judge_pipeline(
        prompts,
        corpus_dir,
        sast_results,
        judge_provider=args.judge_provider,
        judge_model_id=args.judge_model,
        freeze_tag=freeze_tag,
        out_dir=out_dir,
        models_lock=models,
        live=(args.mode == "live"),
    )
    print()

    # 3. Cross-Model Benchmarker
    print("[3/4] Cross-Model Benchmarker")
    benchmark_outputs = run_benchmark_pipeline(
        prompts,
        corpus_dir,
        freeze_tag,
        out_dir,
        models,
        live=(args.mode == "live"),
        max_workers=args.max_workers,
    )
    print()

    # 4. Report Generator
    print("[4/4] Report Generator")
    matrix = build_verdict_matrix(
        prompts,
        sast_results=sast_results,
        judge_verdicts=judge_verdicts,
        cross_model_outputs=benchmark_outputs,
        freeze_tag=freeze_tag,
    )
    summary = summarise(matrix)
    residuals = residual_cwes(matrix)

    export_csv(matrix, out_dir / "verdict_matrix.csv")
    export_json(
        matrix,
        out_dir / "verdict_matrix.json",
        summary=summary,
        residual=residuals,
    )
    render_dashboard(matrix, out_dir / "dashboard.html")
    queue = route_incomplete_rows(matrix, out_path=out_dir / "human_review_queue.json")

    elapsed = int((time.monotonic() - t0) * 1000)
    print()
    print(f"=== Done in {elapsed}ms ===")
    print(f"Verdict matrix: {out_dir / 'verdict_matrix.csv'}")
    print(f"Dashboard:      {out_dir / 'dashboard.html'}")
    print(f"Summary:        {summary}")
    if residuals:
        print(f"Residual CWEs:  {residuals}")
    if queue:
        print(f"Flagged for human review: {len(queue)} rows")
    print()
    print(f"Next step: python scripts/generate_manifest.py --run-dir {out_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
