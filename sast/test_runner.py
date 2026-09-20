"""sast.test_runner — pytest suite for the SAST pipeline (§B.1.3).

Tests three categories per §4.6:
    happy-path     run on a clean snippet returns no findings
    schema         SastResult schema is valid for various inputs
    divergence     overlapping detections are deduplicated, divergent ones retained

These tests are pure-Python unit tests that DO NOT require Bandit or
Semgrep to be installed — they mock the subprocess calls so the
suite is fast and CI-runnable on lightweight runners.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from common.schema import SastFinding, SastResult, SastTool, Severity
from sast.runner import run_bandit, run_semgrep, run_sast
from sast.merger import merge_findings, summarise_agreement, unique_cwes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CLEAN_PY = "def add(a, b):\n    return a + b\n"

SAMPLE_SQLI = (
    "import sqlite3\n"
    "def get_user(username):\n"
    "    conn = sqlite3.connect('app.db')\n"
    "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
    "    cursor.execute(query)\n"
)

SAMPLE_HARDCODED = (
    "password = 'super-secret-123'\n"
)


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


class TestRunBandit:
    def test_clean_source_returns_no_findings(self):
        """A clean Python snippet returns an empty findings list."""
        with patch("sast.runner.shutil.which", return_value="/usr/bin/bandit"):
            with patch("sast.runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout='{"results": []}')
                findings = run_bandit(SAMPLE_CLEAN_PY)
        assert findings == []

    def test_bandit_not_on_path_returns_empty(self):
        """If bandit is not installed, the runner returns empty + warning."""
        with patch("sast.runner.shutil.which", return_value=None):
            findings = run_bandit(SAMPLE_CLEAN_PY)
        assert findings == []

    def test_bandit_parses_findings(self):
        """Bandit JSON output is correctly parsed into SastFinding."""
        bandit_output = {
            "results": [
                {
                    "test_id": "B608",
                    "issue_cwe": {"id": "CWE-89", "link": "..."},
                    "issue_severity": "HIGH",
                    "line_number": 3,
                    "issue_text": "Possible SQL injection",
                    "filename": "<source>",
                }
            ]
        }
        with patch("sast.runner.shutil.which", return_value="/usr/bin/bandit"):
            with patch("sast.runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout=str(bandit_output).replace("'", '"'))
                findings = run_bandit(SAMPLE_SQLI)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-89"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].line == 3
        assert findings[0].tool == SastTool.BANDIT


class TestRunSemgrep:
    def test_semgrep_not_on_path_returns_empty(self):
        with patch("sast.runner.shutil.which", return_value=None):
            findings = run_semgrep(SAMPLE_CLEAN_PY)
        assert findings == []

    def test_semgrep_parses_findings(self):
        """Semgrep JSON output is correctly parsed into SastFinding."""
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.formatted-sql-query",
                    "start": {"line": 4},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Detected SQL injection",
                        "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                    },
                }
            ]
        }
        with patch("sast.runner.shutil.which", return_value="/usr/bin/semgrep"):
            with patch("sast.runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout=str(semgrep_output).replace("'", '"'))
                findings = run_semgrep(SAMPLE_SQLI)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-89"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].tool == SastTool.SEMGREP


# ---------------------------------------------------------------------------
# Schema / integration tests
# ---------------------------------------------------------------------------


class TestRunSast:
    def test_run_sast_returns_valid_schema(self):
        """run_sast() returns a SastResult matching the §B.5.3 schema."""
        with patch("sast.runner._bandit_on_path", return_value=True), \
             patch("sast.runner._semgrep_on_path", return_value=True):
            with patch("sast.runner.run_bandit", return_value=[]):
                with patch("sast.runner.run_semgrep", return_value=[]):
                    result = run_sast("p001", SAMPLE_CLEAN_PY)
        assert isinstance(result, SastResult)
        assert result.prompt_id == "p001"
        assert result.source_sha256  # non-empty
        assert not result.has_finding
        assert result.merged_findings == []

    def test_run_sast_includes_findings(self):
        bandit_finding = SastFinding(
            tool=SastTool.BANDIT,
            rule_id="B608",
            cwe="CWE-89",
            severity=Severity.HIGH,
            file_path="<source>",
            line=3,
            message="SQL injection",
        )
        with patch("sast.runner._bandit_on_path", return_value=True), \
             patch("sast.runner._semgrep_on_path", return_value=True):
            with patch("sast.runner.run_bandit", return_value=[bandit_finding]):
                with patch("sast.runner.run_semgrep", return_value=[]):
                    result = run_sast("p001", SAMPLE_SQLI)
        assert result.has_finding
        assert len(result.merged_findings) == 1
        assert result.merged_findings[0].cwe == "CWE-89"


# ---------------------------------------------------------------------------
# Divergence / overlap tests
# ---------------------------------------------------------------------------


class TestMergeFindings:
    def test_concurrence_bandit_wins(self):
        """When both fire on the same defect, only Bandit is retained."""
        b = [
            SastFinding(
                tool=SastTool.BANDIT, rule_id="B608", cwe="CWE-89",
                severity=Severity.HIGH, file_path="x", line=3,
                message="SQL injection",
            )
        ]
        s = [
            SastFinding(
                tool=SastTool.SEMGREP, rule_id="formatted-sql-query", cwe="CWE-89",
                severity=Severity.HIGH, file_path="x", line=3,
                message="SQL injection",
            )
        ]
        merged = merge_findings(b, s)
        assert len(merged) == 1
        assert merged[0].tool == SastTool.BANDIT

    def test_divergent_findings_retained(self):
        """When CWE or line differs, both findings are kept."""
        b = [
            SastFinding(
                tool=SastTool.BANDIT, rule_id="B608", cwe="CWE-89",
                severity=Severity.HIGH, file_path="x", line=3,
                message="SQL injection",
            )
        ]
        s = [
            SastFinding(
                tool=SastTool.SEMGREP, rule_id="hardcoded-secret", cwe="CWE-798",
                severity=Severity.HIGH, file_path="x", line=10,
                message="hardcoded secret",
            )
        ]
        merged = merge_findings(b, s)
        assert len(merged) == 2

    def test_same_cwe_different_line_retained(self):
        b = [
            SastFinding(
                tool=SastTool.BANDIT, rule_id="B608", cwe="CWE-89",
                severity=Severity.HIGH, file_path="x", line=3,
                message="SQL injection",
            )
        ]
        s = [
            SastFinding(
                tool=SastTool.SEMGREP, rule_id="formatted-sql-query", cwe="CWE-89",
                severity=Severity.HIGH, file_path="x", line=10,
                message="another SQL injection",
            )
        ]
        merged = merge_findings(b, s)
        assert len(merged) == 2


class TestSummariseAgreement:
    def test_no_findings(self):
        r = SastResult(prompt_id="p", source_sha256="x")
        assert summarise_agreement(r) == "no-finding"

    def test_bandit_only(self):
        r = SastResult(
            prompt_id="p",
            source_sha256="x",
            bandit_findings=[
                SastFinding(
                    tool=SastTool.BANDIT, rule_id="B608", cwe="CWE-89",
                    severity=Severity.HIGH, file_path="x", line=3, message="x"
                )
            ],
        )
        assert summarise_agreement(r) == "bandit-only"

    def test_concurrence(self):
        r = SastResult(
            prompt_id="p",
            source_sha256="x",
            bandit_findings=[
                SastFinding(
                    tool=SastTool.BANDIT, rule_id="B608", cwe="CWE-89",
                    severity=Severity.HIGH, file_path="x", line=3, message="x"
                )
            ],
            semgrep_findings=[
                SastFinding(
                    tool=SastTool.SEMGREP, rule_id="x", cwe="CWE-89",
                    severity=Severity.HIGH, file_path="x", line=3, message="x"
                )
            ],
        )
        assert summarise_agreement(r) == "concurrence"


class TestUniqueCwes:
    def test_unique_cwes(self):
        r = SastResult(
            prompt_id="p",
            source_sha256="x",
            bandit_findings=[
                SastFinding(
                    tool=SastTool.BANDIT, rule_id="B608", cwe="CWE-89",
                    severity=Severity.HIGH, file_path="x", line=3, message="x"
                )
            ],
            semgrep_findings=[
                SastFinding(
                    tool=SastTool.SEMGREP, rule_id="x", cwe="CWE-798",
                    severity=Severity.HIGH, file_path="x", line=10, message="y"
                )
            ],
        )
        assert unique_cwes(r) == {"CWE-89", "CWE-798"}
