"""sast — SAST pipeline (Component 1, §4.5, Appendix B.1).

Wraps Bandit and Semgrep as external subprocesses (§B.1.1) and
deduplicates their overlapping detections (§B.1.2) before exposing
a unified SastResult per prompt.

Per §3.5, the SAST tools are deterministic by construction given a
fixed input and a pinned ruleset version — Bandit's default ruleset
is preserved so the defect catalogue stays interpretable against
its published taxonomy, and Semgrep is invoked with the OWASP Top 10
ruleset to give a community-maintained severity anchor.
"""
__version__ = "0.1.0"
