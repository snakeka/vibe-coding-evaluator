"""common.schema — cross-pipeline verdict schema (§B.5.3).

This module defines the Pydantic models that every pipeline emits
into the verdict matrix. Using Pydantic gives us runtime validation
so that the JSON / CSV outputs of one pipeline are guaranteed to be
consumable by the Report Generator (§B.5.1).

Schemas
-------
SastFinding         A single Bandit / Semgrep detection
SastResult          SAST pipeline output for one prompt
JudgeVerdict        LLM-as-Judge pipeline output for one prompt
CrossModelOutput    Cross-Model Benchmarker output for one (prompt, provider)
VerdictRow          One row of the verdict matrix (consumed by Report Generator)
TriangulationClass  Concurrence / partial / divergence enumeration
"""
from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SastTool(str, enum.Enum):
    BANDIT = "bandit"
    SEMGREP = "semgrep"


class JudgeLabel(str, enum.Enum):
    """Discrete Judge verdict (per §B.4.2 constrained output schema)."""

    DEFECT = "defect"
    NO_DEFECT = "no-defect"
    INCONCLUSIVE = "inconclusive"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TriangulationClass(str, enum.Enum):
    """§3.6 verdict classifications produced by Report Generator (§B.5.1).

    concurrence           All three lenses agree
    partial_concurrence   Two of three lenses agree (or one lens absent + two agree)
    divergence            All three lenses disagree pairwise
    incomplete            At least one pipeline did not produce a verdict
    """

    CONCURRENCE = "concurrence"
    PARTIAL_CONCURRENCE = "partial_concurrence"
    DIVERGENCE = "divergence"
    INCOMPLETE = "incomplete"


# ---------------------------------------------------------------------------
# SAST pipeline (§4.5, §B.1)
# ---------------------------------------------------------------------------


class SastFinding(BaseModel):
    """A single Bandit / Semgrep detection (§B.1.2 dedup unit)."""

    tool: SastTool
    rule_id: str
    cwe: str | None = None
    severity: Severity
    file_path: str
    line: int
    message: str

    @field_validator("severity", mode="before")
    @classmethod
    def _normalise_severity(cls, v: object) -> Severity:
        if isinstance(v, Severity):
            return v
        s = str(v).lower()
        mapping = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "warning": Severity.MEDIUM,    # Bandit low/medium both map to medium
            "error": Severity.HIGH,
            "critical": Severity.HIGH,
        }
        return mapping.get(s, Severity.MEDIUM)


class SastResult(BaseModel):
    """SAST pipeline output for one prompt (§4.5, §B.1)."""

    prompt_id: str
    source_sha256: str
    bandit_findings: list[SastFinding] = Field(default_factory=list)
    semgrep_findings: list[SastFinding] = Field(default_factory=list)
    band_exit_code: int = 0
    semgrep_exit_code: int = 0
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def merged_findings(self) -> list[SastFinding]:
        """Deduplicated findings from both tools (§B.1.2)."""
        seen: set[tuple[str, int, str]] = set()
        out: list[SastFinding] = []
        for f in self.bandit_findings + self.semgrep_findings:
            key = (f.cwe or f.rule_id, f.line, f.message[:40])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    @property
    def has_finding(self) -> bool:
        """True if at least one of the two SAST tools fired a rule."""
        return bool(self.bandit_findings or self.semgrep_findings)


# ---------------------------------------------------------------------------
# LLM-as-Judge pipeline (§4.5, §B.2)
# ---------------------------------------------------------------------------


class JudgeVerdict(BaseModel):
    """Judge pipeline output for one prompt (§B.4.2 constrained schema)."""

    prompt_id: str
    source_sha256: str
    label: JudgeLabel
    cwe: str | None = None
    severity: Severity | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    provider: str
    model_id: str
    freeze_tag: str
    audit_log_ref: str | None = None    # path to the audit-log entry

    @field_validator("label", mode="before")
    @classmethod
    def _normalise_label(cls, v: object) -> JudgeLabel:
        if isinstance(v, JudgeLabel):
            return v
        s = str(v).lower().strip().replace("_", "-")
        mapping = {
            "defect": JudgeLabel.DEFECT,
            "no-defect": JudgeLabel.NO_DEFECT,
            "no_defect": JudgeLabel.NO_DEFECT,
            "inconclusive": JudgeLabel.INCONCLUSIVE,
        }
        if s not in mapping:
            return JudgeLabel.INCONCLUSIVE
        return mapping[s]


# ---------------------------------------------------------------------------
# Cross-Model Benchmarker (§4.5, §B.3)
# ---------------------------------------------------------------------------


class CrossModelOutput(BaseModel):
    """Cross-Model Benchmarker output for one (prompt, provider) (§B.3.3 schema)."""

    prompt_id: str
    provider: str
    model_id: str
    language: str
    generated_source: str
    completion_metadata: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict
    )
    latency_ms: int = 0
    freeze_tag: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Verdict matrix row (§B.5)
# ---------------------------------------------------------------------------


class VerdictRow(BaseModel):
    """One row of the verdict matrix (§B.5.1, §B.5.2)."""

    prompt_id: str
    source_sha256: str
    language: str
    task: str

    # SAST
    sast_verdict: Literal["defect", "no-defect", "no-finding"] | None = None
    sast_findings_count: int = 0

    # Judge
    judge_verdict: JudgeLabel | None = None
    judge_cwe: str | None = None
    judge_severity: Severity | None = None
    judge_confidence: float | None = None

    # Cross-model agreement (defect-yes/no across providers)
    cross_model_defect_yes: int = 0
    cross_model_defect_no: int = 0
    cross_model_defect_inconclusive: int = 0

    # Triangulation
    triangulation: TriangulationClass = TriangulationClass.INCOMPLETE
    residual_flag: str | None = None

    # Provenance
    freeze_tag: str

    @classmethod
    def from_components(
        cls,
        prompt_id: str,
        source_sha256: str,
        language: str,
        task: str,
        sast: SastResult | None,
        judge: JudgeVerdict | None,
        cross_model_outputs: list[CrossModelOutput],
        freeze_tag: str,
    ) -> "VerdictRow":
        """Build a VerdictRow from the three pipeline outputs (§B.5.1)."""
        # SAST verdict: defect if either tool fired, no-defect if both ran cleanly
        sast_verdict: str | None
        sast_count = 0
        if sast is not None:
            if sast.has_finding:
                sast_verdict = "defect"
                sast_count = len(sast.merged_findings)
            elif sast.error:
                sast_verdict = None
            else:
                sast_verdict = "no-defect"
        else:
            sast_verdict = None

        # Cross-model defect counts (apply simple SAST-or-keyword heuristic on
        # the generated_source — the §5.5 cross-model reporting carries a more
        # sophisticated analysis upstream; this row carries the operational
        # counts that the Report Generator needs).
        cross_yes = sum(
            1
            for o in cross_model_outputs
            if o.error is None
            and ("defect" in o.completion_metadata.get("static_label", "").lower())
        )
        cross_no = sum(
            1
            for o in cross_model_outputs
            if o.error is None
            and ("no-defect" in o.completion_metadata.get("static_label", "").lower())
        )
        cross_inc = sum(
            1
            for o in cross_model_outputs
            if o.error is None
            and ("inconclusive" in o.completion_metadata.get("static_label", "").lower())
        )

        # Triangulation (§3.6 rules)
        # A "lens" is a pipeline that actually produced a verdict:
        # SAST ran and returned either defect/no-defect; Judge produced
        # a verdict; cross-model produced at least one output.
        sast_lens = sast_verdict is not None
        judge_lens = judge is not None
        cross_lens = len(cross_model_outputs) > 0
        present_lenses = sum([sast_lens, judge_lens, cross_lens])

        if present_lenses < 2:
            tri = TriangulationClass.INCOMPLETE
            residual = None
        else:
            # Build label sets across lenses
            labels: set[str] = set()
            if sast_verdict:
                labels.add(sast_verdict)
            if judge is not None:
                labels.add(judge.label.value)
            if cross_model_outputs:
                # Majority cross-model label
                cm_labels = [
                    o.completion_metadata.get("static_label", "inconclusive")
                    for o in cross_model_outputs
                    if o.error is None
                ]
                if cm_labels:
                    from collections import Counter

                    majority = Counter(cm_labels).most_common(1)[0][0]
                    labels.add(majority)

            if len(labels) == 1:
                tri = TriangulationClass.CONCURRENCE
                residual = None
            elif len(labels) == 2:
                tri = TriangulationClass.PARTIAL_CONCURRENCE
                # If SAST is absent and Judge + cross-model agree on defect,
                # that is the CWE-20/CWE-79 residual pattern from §5.3
                if sast_verdict is None and judge and judge.label == JudgeLabel.DEFECT:
                    residual = judge.cwe or "unknown"
                else:
                    residual = None
            else:
                tri = TriangulationClass.DIVERGENCE
                residual = None

        return cls(
            prompt_id=prompt_id,
            source_sha256=source_sha256,
            language=language,
            task=task,
            sast_verdict=sast_verdict,
            sast_findings_count=sast_count,
            judge_verdict=judge.label if judge else None,
            judge_cwe=judge.cwe if judge else None,
            judge_severity=judge.severity if judge else None,
            judge_confidence=judge.confidence if judge else None,
            cross_model_defect_yes=cross_yes,
            cross_model_defect_no=cross_no,
            cross_model_defect_inconclusive=cross_inc,
            triangulation=tri,
            residual_flag=residual,
            freeze_tag=freeze_tag,
        )
