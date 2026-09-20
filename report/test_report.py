"""report tests — verdict merger + divergence router + exporter.

Pure-Python unit tests covering the §B.5 logic.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from common.schema import (
    CrossModelOutput,
    JudgeLabel,
    JudgeVerdict,
    SastFinding,
    SastResult,
    SastTool,
    Severity,
    TriangulationClass,
    VerdictRow,
)
from report.verdict_merger import build_verdict_matrix, summarise, residual_cwes
from report.divergence_router import route_incomplete_rows, queue_by_reason
from report.exporter import export_csv, export_json, render_dashboard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def freeze_tag() -> str:
    return "vce-2026-09-20-frozen"


@pytest.fixture
def sample_sast_defect(freeze_tag) -> SastResult:
    return SastResult(
        prompt_id="p001",
        source_sha256="abc123",
        bandit_findings=[
            SastFinding(
                tool=SastTool.BANDIT,
                rule_id="B608",
                cwe="CWE-89",
                severity=Severity.HIGH,
                file_path="<source>",
                line=3,
                message="SQL injection",
            )
        ],
    )


@pytest.fixture
def sample_judge_defect(freeze_tag) -> JudgeVerdict:
    return JudgeVerdict(
        prompt_id="p001",
        source_sha256="abc123",
        label=JudgeLabel.DEFECT,
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.9,
        evidence="SQL injection on line 3",
        provider="ollama",
        model_id="qwen2.5-coder:32b",
        freeze_tag=freeze_tag,
    )


@pytest.fixture
def sample_cross_model(freeze_tag) -> list[CrossModelOutput]:
    return [
        CrossModelOutput(
            prompt_id="p001",
            provider="ollama",
            model_id="qwen2.5-coder:32b",
            language="python",
            generated_source='password = "x"',
            completion_metadata={"static_label": "defect"},
            freeze_tag=freeze_tag,
        ),
        CrossModelOutput(
            prompt_id="p001",
            provider="openai",
            model_id="codex",
            language="python",
            generated_source='password = "x"',
            completion_metadata={"static_label": "defect"},
            freeze_tag=freeze_tag,
        ),
    ]


@pytest.fixture
def sample_prompts() -> list[dict]:
    return [
        {"prompt_id": "p001", "language": "python", "task": "function_completion"},
    ]


# ---------------------------------------------------------------------------
# Verdict merger tests
# ---------------------------------------------------------------------------


class TestBuildVerdictMatrix:
    def test_concurrence_when_all_agree(
        self, sample_prompts, sample_sast_defect, sample_judge_defect, sample_cross_model, freeze_tag
    ):
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={"p001": sample_sast_defect},
            judge_verdicts={"p001": sample_judge_defect},
            cross_model_outputs=sample_cross_model,
            freeze_tag=freeze_tag,
        )
        assert len(matrix) == 1
        row = matrix[0]
        assert row.triangulation == TriangulationClass.CONCURRENCE

    def test_residual_flag_when_sast_absent_and_others_agree(
        self, sample_prompts, sample_judge_defect, freeze_tag
    ):
        # SAST absent + Judge defect + 1 cross-model "no-defect" → 2 labels
        # → partial_concurrence with the CWE-89 residual flag.
        cross = [
            CrossModelOutput(
                prompt_id="p001",
                provider="openai",
                model_id="codex",
                language="python",
                generated_source="",
                completion_metadata={"static_label": "no-defect"},
                freeze_tag=freeze_tag,
            )
        ]
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={},
            judge_verdicts={"p001": sample_judge_defect},
            cross_model_outputs=cross,
            freeze_tag=freeze_tag,
        )
        row = matrix[0]
        # Judge says "defect", cross-model says "no-defect" → 2 labels → partial
        assert row.triangulation == TriangulationClass.PARTIAL_CONCURRENCE
        # §5.6 residual pattern: SAST absent, Judge is load-bearing for the defect call
        assert row.residual_flag == "CWE-89"

    def test_incomplete_when_only_judge_missing(
        self, sample_prompts, sample_sast_defect, freeze_tag
    ):
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={"p001": sample_sast_defect},
            judge_verdicts={},
            cross_model_outputs=[],
            freeze_tag=freeze_tag,
        )
        row = matrix[0]
        # SAST alone is one lens → incomplete
        assert row.triangulation == TriangulationClass.INCOMPLETE


class TestSummarise:
    def test_summarise(self, sample_prompts, sample_sast_defect, sample_judge_defect, sample_cross_model, freeze_tag):
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={"p001": sample_sast_defect},
            judge_verdicts={"p001": sample_judge_defect},
            cross_model_outputs=sample_cross_model,
            freeze_tag=freeze_tag,
        )
        s = summarise(matrix)
        assert s["concurrence"] == 1
        assert s["partial_concurrence"] == 0


# ---------------------------------------------------------------------------
# Divergence router tests
# ---------------------------------------------------------------------------


class TestDivergenceRouter:
    def test_flag_incomplete(self, sample_prompts, freeze_tag):
        # Build a matrix with one INCOMPLETE row
        row = VerdictRow(
            prompt_id="p001",
            source_sha256="x",
            language="python",
            task="function_completion",
            freeze_tag=freeze_tag,
        )
        # Single lens = INCOMPLETE
        assert row.triangulation == TriangulationClass.INCOMPLETE
        queue = route_incomplete_rows([row])
        assert len(queue) == 1

    def test_flag_writes_json(self, tmp_path, sample_prompts, freeze_tag):
        row = VerdictRow(
            prompt_id="p001",
            source_sha256="x",
            language="python",
            task="function_completion",
            freeze_tag=freeze_tag,
        )
        out = tmp_path / "queue.json"
        queue = route_incomplete_rows([row], out_path=out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["n_flagged"] == 1


# ---------------------------------------------------------------------------
# Exporter tests
# ---------------------------------------------------------------------------


class TestExporter:
    def test_export_csv(self, tmp_path, sample_prompts, sample_sast_defect, sample_judge_defect, sample_cross_model, freeze_tag):
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={"p001": sample_sast_defect},
            judge_verdicts={"p001": sample_judge_defect},
            cross_model_outputs=sample_cross_model,
            freeze_tag=freeze_tag,
        )
        path = export_csv(matrix, tmp_path / "matrix.csv")
        assert path.exists()
        with path.open() as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["prompt_id"] == "p001"
        assert rows[0]["triangulation"] == "concurrence"

    def test_export_json(self, tmp_path, sample_prompts, sample_sast_defect, sample_judge_defect, sample_cross_model, freeze_tag):
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={"p001": sample_sast_defect},
            judge_verdicts={"p001": sample_judge_defect},
            cross_model_outputs=sample_cross_model,
            freeze_tag=freeze_tag,
        )
        path = export_json(matrix, tmp_path / "matrix.json")
        data = json.loads(path.read_text())
        assert data["n_rows"] == 1
        assert data["rows"][0]["prompt_id"] == "p001"

    def test_render_dashboard(self, tmp_path, sample_prompts, sample_sast_defect, sample_judge_defect, sample_cross_model, freeze_tag):
        matrix = build_verdict_matrix(
            sample_prompts,
            sast_results={"p001": sample_sast_defect},
            judge_verdicts={"p001": sample_judge_defect},
            cross_model_outputs=sample_cross_model,
            freeze_tag=freeze_tag,
        )
        path = render_dashboard(matrix, tmp_path / "dashboard.html")
        html = path.read_text()
        assert "Vibe Coding Evaluation" in html
        assert "p001" in html
        assert "concurrence" in html
