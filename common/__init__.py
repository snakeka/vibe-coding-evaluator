"""common — shared utilities for the four-pipeline evaluation framework.

This package hosts the substrate modules that all four pipelines
(SAST, Judge, Cross-Model, Report) depend on. Keeping them in one
place enforces the §4.3 cross-pipeline schema commitment (§B.5.3)
and the §3.5 freeze commitment (§B.6).

Modules
-------
config     YAML / .env / lock-file loader with freeze-tag validation
hashing    SHA-256 helpers + deterministic seeded RNG
schema     Pydantic models for the cross-pipeline verdict schema
fixtures   The 3 illustrative samples (§5.6 Table 5.7)
"""
__version__ = "0.1.0"
