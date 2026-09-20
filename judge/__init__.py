"""judge — LLM-as-Judge pipeline (Components 2 + 4, §4.5, §B.2, §B.4).

Implements the MT-Bench-structured prompt template, the three bias
controls (position, verbosity, self-enhancement), the per-bias
detection driver, and the append-only audit log sealed into the
per-run SHA-256 manifest.

Public entry points:
    judge.orchestrator.judge(prompt_id, source, sast_flags, ...) -> JudgeVerdict
    judge.audit_log.write(record) -> None
    judge.bias_detector.run_full_protocol(samples, freeze_tag) -> BiasSummary
"""
__version__ = "0.1.0"
