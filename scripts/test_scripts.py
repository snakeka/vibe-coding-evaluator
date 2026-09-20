"""scripts tests — end-to-end run + manifest generation.

These tests exercise the full pipeline against the 3 illustrative
samples in stub mode (no live LLM calls). They verify the run
produces the expected verdict matrix + manifest artefacts.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# End-to-end run test (stub mode)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def run_dir(tmp_path_factory) -> Path:
    """Run the full pipeline once and return the run directory."""
    out_dir = tmp_path_factory.mktemp("run")
    # Run via subprocess so PYTHONPATH is clean
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_full_evaluation.py",
            "--out", str(out_dir),
            "--mode", "stub",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    assert result.returncode == 0, f"run failed: {result.stderr}"
    return out_dir


class TestEndToEnd:
    def test_run_creates_verdict_csv(self, run_dir):
        assert (run_dir / "verdict_matrix.csv").exists()

    def test_run_creates_verdict_json(self, run_dir):
        assert (run_dir / "verdict_matrix.json").exists()

    def test_run_creates_dashboard(self, run_dir):
        assert (run_dir / "dashboard.html").exists()

    def test_run_creates_sast_artefacts(self, run_dir):
        sast_files = list((run_dir / "sast").glob("*.json"))
        assert len(sast_files) == 3

    def test_run_creates_judge_audit(self, run_dir):
        audit = run_dir / "judge" / "audit.jsonl"
        assert audit.exists()
        lines = audit.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_run_creates_benchmark_artefacts(self, run_dir):
        bench_files = list((run_dir / "benchmark").glob("*.json"))
        # 3 prompts × 5 providers = 15 files
        assert len(bench_files) == 15

    def test_verdict_matrix_has_three_rows(self, run_dir):
        data = json.loads((run_dir / "verdict_matrix.json").read_text())
        assert data["n_rows"] == 3

    def test_triangulation_distribution(self, run_dir):
        data = json.loads((run_dir / "verdict_matrix.json").read_text())
        summary = data["summary"]
        # All three illustrative samples should produce a classification
        # (concurrence / partial_concurrence / divergence / incomplete)
        # — at least one of the three buckets must have ≥ 1 row.
        assert sum(summary.values()) == 3

    def test_dashboard_renders_prompt_ids(self, run_dir):
        html = (run_dir / "dashboard.html").read_text()
        assert "p001-sqli-function-completion" in html
        assert "p002-hardcoded-password-bugfix" in html
        assert "p003-missing-validation-refactor" in html


class TestManifestGeneration:
    @pytest.fixture(scope="module")
    def run_with_manifest(self, tmp_path_factory):
        """Run the full pipeline + manifest, return the run dir."""
        out_dir = tmp_path_factory.mktemp("run-manifest")
        env = {**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT)}

        result1 = subprocess.run(
            [sys.executable, "scripts/run_full_evaluation.py",
             "--out", str(out_dir), "--mode", "stub"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, env=env,
        )
        assert result1.returncode == 0

        result2 = subprocess.run(
            [sys.executable, "scripts/generate_manifest.py",
             "--run-dir", str(out_dir)],
            cwd=str(REPO_ROOT), capture_output=True, text=True, env=env,
        )
        assert result2.returncode == 0
        return out_dir

    def test_manifest_file_created(self, run_with_manifest):
        assert (run_with_manifest / "manifest.sha256").exists()

    def test_manifest_self_seal_line(self, run_with_manifest):
        first_line = (run_with_manifest / "manifest.sha256").read_text().splitlines()[0]
        assert first_line.endswith("manifest.sha256")

    def test_manifest_lists_all_artefacts(self, run_with_manifest):
        lines = (run_with_manifest / "manifest.sha256").read_text().strip().splitlines()
        # Self-seal + at least verdict_matrix.csv + verdict_matrix.json + dashboard.html
        assert len(lines) >= 4
        artefacts = " ".join(lines)
        assert "verdict_matrix.csv" in artefacts
        assert "verdict_matrix.json" in artefacts
        assert "dashboard.html" in artefacts
