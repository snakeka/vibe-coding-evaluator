"""Illustrative sample 3 — Missing input validation (CWE-20) — refactor.

Per §5.6 Table 5.7 (illustrative truncation: 2e9d...).
Neither Bandit nor Semgrep's default rulesets detect this defect;
the LLM-as-Judge overlay is load-bearing for CWE-20 detection here.

Expected triangulation: partial concurrence with CWE-20 residual flag
(SAST absent; Judge + human raters + cross-model agree).
"""


def process_age(age_str):
    """Classify a person as adult or minor based on an age string."""
    # SECURITY DEFECT: no validation on age_str — int() raises on
    # non-numeric input (uncaught exception), and a negative age
    # bypasses the >0 check is not possible here but arbitrary
    # non-integer strings are accepted through ValueError leakage.
    age = int(age_str)
    if age > 0:
        return f"Adult: {age}"
    return f"Minor: {age}"
