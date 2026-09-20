"""scripts — end-to-end driver scripts.

This package hosts the entry-point scripts that orchestrate a full
evaluation run. They are thin wrappers over the four pipeline
modules and are kept out of the package distribution (per
pyproject.toml's ``exclude = ["scripts*"]``).

Entry points:
    scripts.run_full_evaluation       Run the 4 pipelines end-to-end
    scripts.generate_manifest         Compute the SHA-256 manifest
    scripts.generate_corpus           Generate the §3.5 200-prompt corpus
"""
