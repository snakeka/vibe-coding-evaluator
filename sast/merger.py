"""sast.merger — deduplication of overlapping SAST detections (§B.1.2).

Per §3.4, the two SAST tools operate as complementary lenses — when
both fire on the same defect, that is *concurrence* (a stronger
signal); when one fires and the other does not, that is *partial
concurrence* or *divergence* (also informative per §2.6).

This module implements the dedup rule: two detections are
considered overlapping when they share the same CWE category AND
target the same source line. In that case, only one entry is
retained (the Bandit one wins as the canonical tool, since Bandit's
default ruleset is the published reference taxonomy per §B.1.1).

Divergent detections are always retained.
"""
from __future__ import annotations

from common.schema import SastFinding, SastResult, SastTool


def merge_findings(
    bandit: list[SastFinding],
    semgrep: list[SastFinding],
) -> list[SastFinding]:
    """Merge Bandit + Semgrep findings, deduplicating overlapping detections.

    Overlap rule (per §B.1.2):
        Two detections overlap if they share the same CWE category
        AND the same source line. In that case, the Bandit finding
        wins as the canonical entry (its rule_id is more stable for
        cross-run comparison).

    Divergent detections (different CWE or different line) are always
    retained as separate findings.
    """
    merged: list[SastFinding] = list(bandit)  # Bandit wins on overlap

    for sf in semgrep:
        overlap = any(
            bf.cwe == sf.cwe
            and bf.cwe is not None
            and bf.line == sf.line
            for bf in bandit
        )
        if not overlap:
            merged.append(sf)

    return merged


def summarise_agreement(result: SastResult) -> str:
    """Return a string describing the Bandit-Semgrep agreement for a run.

    Used by §3.6 triangulation reporting. One of:
        concurrence           Both fire on the same defect
        partial_concurrence   One fires, the other does not
        no-finding            Neither fires
        bandit-only           Only Bandit fires
        semgrep-only          Only Semgrep fires
    """
    b_fired = bool(result.bandit_findings)
    s_fired = bool(result.semgrep_findings)

    if not b_fired and not s_fired:
        return "no-finding"

    if b_fired and s_fired:
        # Check whether they share at least one overlap
        for bf in result.bandit_findings:
            for sf in result.semgrep_findings:
                if (
                    bf.cwe is not None
                    and bf.cwe == sf.cwe
                    and bf.line == sf.line
                ):
                    return "concurrence"
        return "partial_concurrence"

    if b_fired:
        return "bandit-only"
    return "semgrep-only"


def unique_cwes(result: SastResult) -> set[str]:
    """Return the set of distinct CWE categories across both tools."""
    cwes: set[str] = set()
    for f in result.bandit_findings + result.semgrep_findings:
        if f.cwe:
            cwes.add(f.cwe)
    return cwes
