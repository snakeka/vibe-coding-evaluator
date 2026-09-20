"""judge.audit_log — append-only audit writer (§B.4.4).

Per §B.4.4, every Judge call records:
    caller, prompt_id, provider, model_id, seed, ordering_key,
    response, latency_ms, leakage_check_status

into an append-only JSONL file at ``results/<run-id>/judge/audit.jsonl``.
The file is sealed into the per-run ``manifest.sha256`` at run
completion via scripts/generate_manifest.py.

The audit_log module is the single source of truth for §3.7's
sealing commitment for the Judge pipeline. Any modification of an
audit-log entry breaks the SHA-256 manifest, which is detected on
the next re-execution.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from common.hashing import sha256_str


@dataclass
class AuditRecord:
    """One Judge-call audit record (§B.4.4)."""

    timestamp: str
    caller: str                  # orchestrator / bias_detector / unit_test
    prompt_id: str
    freeze_tag: str
    provider: str
    model_id: str
    seed: int | None
    ordering_key: int | None
    response: str
    latency_ms: int
    leakage_check_passed: bool
    leakage_violations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    """Append-only audit writer (§B.4.4).

    Usage
    -----

    >>> log = AuditLog("results/run-2026-09-20/judge/audit.jsonl")
    >>> log.write(AuditRecord(...))
    >>> log.close()
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a", buffering=1)  # line-buffered
        self._record_count = 0

    def write(self, record: AuditRecord) -> None:
        """Append a single record as a JSON line."""
        self._file.write(json.dumps(asdict(record)) + "\n")
        self._record_count += 1

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    @property
    def record_count(self) -> int:
        return self._record_count

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def verify_no_leakage(record: AuditRecord) -> bool:
    """String-match the prompt against the leakage_strings (§B.4.3).

    Per §B.4.3: "The control is verified at run time by string-
    matching the audit log against the prompt template — any leakage
    aborts the run with a §3.7 manifest mismatch".

    Returns True if no leakage is detected.
    """
    leakage_strings = record.metadata.get("leakage_strings", [])
    prompt = record.metadata.get("prompt_text", "")
    return not any(s and s in prompt for s in leakage_strings)


def make_audit_record(
    *,
    caller: str,
    prompt_id: str,
    freeze_tag: str,
    provider: str,
    model_id: str,
    seed: int | None,
    ordering_key: int | None,
    response: str,
    prompt_text: str,
    leakage_strings: list[str],
    start_time: float,
    metadata: dict[str, Any] | None = None,
) -> AuditRecord:
    """Construct a fully-populated AuditRecord with leakage check done."""
    latency_ms = int((time.monotonic() - start_time) * 1000)
    leakage_violations = [
        s for s in leakage_strings if s and s in prompt_text
    ]
    md = dict(metadata or {})
    md["leakage_strings"] = leakage_strings
    md["prompt_text"] = prompt_text
    return AuditRecord(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        caller=caller,
        prompt_id=prompt_id,
        freeze_tag=freeze_tag,
        provider=provider,
        model_id=model_id,
        seed=seed,
        ordering_key=ordering_key,
        response=response,
        latency_ms=latency_ms,
        leakage_check_passed=not leakage_violations,
        leakage_violations=leakage_violations,
        metadata=md,
    )


def sha256_audit_log(path: Path | str) -> str:
    """SHA-256 of the audit-log file (for the run manifest)."""
    from common.hashing import sha256_file
    return sha256_file(path)
