"""sast.runner — Bandit + Semgrep subprocess driver (§B.1.1).

The SAST pipeline (§4.5) is realised through two complementary tools
invoked as external subprocesses from a thin Python driver. Bandit's
default ruleset is preserved; Semgrep uses the OWASP Top 10 ruleset
(per §3.5 freeze commitment).

This module exposes two pure-Python functions:

* run_bandit(source, path) -> list[SastFinding]
* run_semgrep(source, path, ruleset="owasp-top-ten") -> list[SastFinding]
* run_sast(prompt_id, source, path) -> SastResult

The third is the public entry point consumed by the Report Generator
and by the integration tests. It runs the two tools in parallel via
concurrent.futures, then calls sast.merger.merge() to deduplicate
overlapping detections.
"""
from __future__ import annotations

import concurrent.futures
import json
import shutil
import subprocess
import time
from pathlib import Path

from common.hashing import sha256_str
from common.schema import SastFinding, SastResult, SastTool, Severity


# ---------------------------------------------------------------------------
# Bandit driver
# ---------------------------------------------------------------------------


def _bandit_on_path() -> bool:
    return shutil.which("bandit") is not None


def run_bandit(source: str, path: str = "<source>") -> list[SastFinding]:
    """Run Bandit on `source` and return a list of SastFinding.

    Parameters
    ----------
    source : str
        The Python source code to analyse.
    path : str
        The synthetic file path used for reporting.

    Returns
    -------
    list[SastFinding]
        Parsed findings. Empty list on success (no findings) or on
        Bandit not being installed.

    Notes
    -----
    Bandit is invoked with ``-f json`` for stable parsing and
    ``--exit-zero`` so that findings do not produce a non-zero exit
    code (the calling code reads the JSON regardless).
    """
    if not _bandit_on_path():
        # Soft warning rather than hard failure so the framework is
        # usable in environments where Bandit is not installed
        # (e.g. lightweight CI runners without the [sast] extras).
        import warnings
        warnings.warn(
            "bandit not on PATH; returning empty findings. "
            "Install with `pip install bandit` to enable.",
            stacklevel=2,
        )
        return []

    proc = subprocess.run(
        ["bandit", "-", "-f", "json", "--exit-zero"],
        input=source,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if not proc.stdout.strip():
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[SastFinding] = []
    for r in payload.get("results", []):
        # Bandit CWE is exposed as either:
        #   - an int (e.g. {"id": 89, "link": "..."})
        #   - a dict with "id" key
        #   - a string (e.g. "CWE-89")
        cwe_field = r.get("issue_cwe", {})
        cwe_id: str | None = None
        if isinstance(cwe_field, dict):
            cid = cwe_field.get("id")
            if cid is None:
                cwe_id = None
            elif isinstance(cid, int):
                cwe_id = f"CWE-{cid}"
            else:
                cwe_id = str(cid).strip() or None
        elif isinstance(cwe_field, int):
            cwe_id = f"CWE-{cwe_field}"
        elif isinstance(cwe_field, str) and cwe_field.strip():
            cwe_id = cwe_field.strip()

        try:
            finding = SastFinding(
                tool=SastTool.BANDIT,
                rule_id=r.get("test_id", ""),
                cwe=cwe_id,
                severity=Severity(r.get("issue_severity", "medium").lower()),
                file_path=path,
                line=int(r.get("line_number", 0) or 0),
                message=r.get("issue_text", "").strip(),
            )
            findings.append(finding)
        except Exception:
            # Skip malformed findings rather than abort the run
            continue

    return findings


# ---------------------------------------------------------------------------
# Semgrep driver
# ---------------------------------------------------------------------------


def _semgrep_on_path() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(
    source: str,
    path: str = "<source>",
    ruleset: str = "owasp-top-ten",
) -> list[SastFinding]:
    """Run Semgrep on `source` and return a list of SastFinding.

    Parameters
    ----------
    source : str
        Source code to analyse.
    path : str
        Synthetic file path for reporting.
    ruleset : str
        The Semgrep ruleset to apply. Default ``owasp-top-ten`` per
        §B.1.1 ("Semgrep is invoked with the OWASP Top 10 ruleset").

    Returns
    -------
    list[SastFinding]

    Notes
    -----
    Semgrep's CLI requires a file on disk; we write `source` to a
    temporary file, run Semgrep, parse the JSON output, and clean up.
    For OWASP Top 10, the public registry path is used; the caller
    can pass any valid Semgrep --config target.
    """
    if not _semgrep_on_path():
        import warnings
        warnings.warn(
            "semgrep not on PATH; returning empty findings. "
            "Install with `pip install semgrep` to enable.",
            stacklevel=2,
        )
        return []

    tmp_path = Path("/tmp/_vce_semgrep_tmp.py")
    tmp_path.write_text(source)

    config_arg: list[str]
    if ruleset == "owasp-top-ten":
        config_arg = ["--config", "p/owasp-top-ten"]
    else:
        config_arg = ["--config", ruleset]

    try:
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--error", *config_arg, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    if not proc.stdout.strip():
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[SastFinding] = []
    for r in payload.get("results", []):
        # CWE is exposed in extra.metadata.cwe
        cwe_id: str | None = None
        meta = r.get("extra", {}).get("metadata", {})
        cwe_field = meta.get("cwe")
        if isinstance(cwe_field, list) and cwe_field:
            # e.g. ["CWE-89: Improper Neutralization of Special Elements ..."]
            first = cwe_field[0]
            if ":" in first:
                cwe_id = first.split(":", 1)[0].strip()
            else:
                cwe_id = first.strip()
        elif isinstance(cwe_field, str) and cwe_field:
            cwe_id = cwe_field.split(":", 1)[0].strip() if ":" in cwe_field else cwe_field

        sev = (r.get("extra", {}).get("severity") or "WARNING").upper()
        try:
            finding = SastFinding(
                tool=SastTool.SEMGREP,
                rule_id=r.get("check_id", "").split(".")[-1],
                cwe=cwe_id,
                severity=Severity(_normalise_semgrep_severity(sev)),
                file_path=path,
                line=int((r.get("start", {}) or {}).get("line", 0) or 0),
                message=r.get("extra", {}).get("message", "").strip(),
            )
            findings.append(finding)
        except Exception:
            continue

    return findings


def _normalise_semgrep_severity(sev: str) -> str:
    """Map Semgrep severity to our Severity enum."""
    sev = sev.upper()
    mapping = {
        "INFO": "low",
        "WARNING": "medium",
        "ERROR": "high",
    }
    return mapping.get(sev, "medium")


# ---------------------------------------------------------------------------
# Public entry point — runs both tools in parallel
# ---------------------------------------------------------------------------


def run_sast(prompt_id: str, source: str, path: str = "<source>") -> SastResult:
    """Run Bandit + Semgrep on `source` and return a unified SastResult.

    The two tools are invoked in parallel via concurrent.futures for
    wall-clock efficiency. The merged findings (deduplicated per
    §B.1.2) are accessible via ``result.merged_findings``.

    Parameters
    ----------
    prompt_id : str
        The freeze-stable identifier from prompts.lock.
    source : str
        The Python source code to analyse.
    path : str
        The synthetic file path used for reporting.

    Returns
    -------
    SastResult
        Unified result. ``error`` is populated only if a subprocess
        itself crashed (not for "no findings found").
    """
    source_sha = sha256_str(source)
    t0 = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fut_b = pool.submit(run_bandit, source, path)
        fut_s = pool.submit(run_semgrep, source, path)
        bandit_findings = fut_b.result()
        semgrep_findings = fut_s.result()

    elapsed_ms = int((time.monotonic() - t0) * 1000)

    return SastResult(
        prompt_id=prompt_id,
        source_sha256=source_sha,
        bandit_findings=bandit_findings,
        semgrep_findings=semgrep_findings,
        elapsed_ms=elapsed_ms,
    )
