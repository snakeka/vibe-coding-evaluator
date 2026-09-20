"""Illustrative sample 2 — Hardcoded password (CWE-798) — bug fix.

Per §5.6 Table 5.7 (illustrative truncation: b7c4...).
Bandit (B105 hardcoded_password_string) detects by default; Semgrep
may miss without a tuned ruleset.

Expected triangulation: partial concurrence (Bandit + Judge + cross-model
agree; Semgrep absent).
"""
import psycopg2


def connect_to_db():
    """Connect to the production customer database."""
    # SECURITY DEFECT: hardcoded credential embedded in source.
    conn = psycopg2.connect(
        host="prod-db.example.com",
        database="customers",
        user="admin",
        password="Adm1nP@ss2024",
    )
    return conn
