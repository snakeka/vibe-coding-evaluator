"""scripts.generate_manifest — compute the SHA-256 manifest (§B.6).

Per §3.7 / §B.6.4, the per-run manifest seals the input corpus, the
per-pipeline result files and the verdict matrix into a single
manifest.sha256 file. Any post-hoc modification of those files is
detectable on the next re-execution.

Usage
-----

    python scripts/generate_manifest.py --run-dir results/run-2026-09-20-001/

This script:
    1. Walks the run directory and identifies all artefact files
    2. Computes SHA-256 over each
    3. Writes ``<run-dir>/manifest.sha256`` with the format:
        <sha256>  <relative-path>
       <sha256>  manifest.sha256          ← self-seal at the top
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as `python scripts/generate_manifest.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.hashing import sha256_file, sha256_str


# Files that contribute to the manifest. Add new artefact kinds here
# as new pipelines / outputs are added.
_MANIFEST_INPUTS = [
    "verdict_matrix.csv",
    "verdict_matrix.json",
    "dashboard.html",
    "human_review_queue.json",
    "judge/bias_summary.json",
    "judge/audit.jsonl",
]


def collect_artefacts(run_dir: Path) -> list[Path]:
    """Collect every artefact that should be sealed into the manifest."""
    found: list[Path] = []
    for rel in _MANIFEST_INPUTS:
        p = run_dir / rel
        if p.exists():
            found.append(p)
    # Add all per-prompt SAST / benchmark outputs
    for sub in ("sast", "benchmark"):
        d = run_dir / sub
        if d.exists():
            for p in sorted(d.glob("*.json")):
                found.append(p)
    return found


def write_manifest(run_dir: Path) -> str:
    """Compute the manifest and write it. Returns the seal hash."""
    artefacts = collect_artefacts(run_dir)
    lines = []
    for p in artefacts:
        rel = p.relative_to(run_dir)
        digest = sha256_file(p)
        lines.append(f"{digest}  {rel}")

    body = "\n".join(lines) + "\n"
    # Compute the self-seal over the body
    seal = sha256_str(body)
    final = f"{seal}  manifest.sha256\n{body}"

    out_path = run_dir / "manifest.sha256"
    out_path.write_text(final)
    return seal


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the SHA-256 run manifest.")
    parser.add_argument("--run-dir", required=True, help="Path to the run directory")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Run directory does not exist: {run_dir}", file=sys.stderr)
        return 1

    seal = write_manifest(run_dir)
    print(f"Manifest written: {run_dir / 'manifest.sha256'}")
    print(f"Self-seal:        {seal}")
    print(f"Artefacts sealed: {len(collect_artefacts(run_dir))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
