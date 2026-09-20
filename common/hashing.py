"""common.hashing — SHA-256 helpers and deterministic seeded RNG.

Implements the §B.6 freeze sealing commitment: every input corpus
file, per-pipeline result file and the verdict matrix are SHA-256
hashed at run completion and the hashes are sealed into
``manifest.sha256``. Any post-hoc modification is detectable on the
next re-execution (§3.7).

The deterministic-seeded RNG (§B.4.1, §B.6.4) is provided so that the
position-bias control's ``random.shuffle`` and the per-call seed
selection are reproducible across machines for the same freeze_tag.
"""
from __future__ import annotations

import hashlib
import random
from pathlib import Path


def sha256_file(path: Path | str) -> str:
    """SHA-256 of a file's contents (streaming)."""
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_str(s: str) -> str:
    """SHA-256 of a UTF-8 string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hash_prompt_with_freeze(prompt_text: str, freeze_tag: str) -> str:
    """SHA-256 of (prompt_text || freeze_tag) for §3.5 prompt ID derivation.

    The freeze tag is salted so that derived hashes are reproducible
    across machines for the same freeze_tag — preventing hash
    collisions if the same prompt text appears in a different freeze.
    """
    return sha256_str(f"{prompt_text}||{freeze_tag}")


def seeded_rng(freeze_tag: str, prompt_id: str) -> random.Random:
    """A random.Random instance seeded from (freeze_tag, prompt_id).

    Used by the position-bias control (§B.4.1) and by the per-call
    seed selector (§B.6.4) so that re-execution against the same
    freeze reproduces the same orderings and seed values.
    """
    seed_material = f"{freeze_tag}::{prompt_id}"
    seed_int = int(sha256_str(seed_material)[:16], 16)
    return random.Random(seed_int)


def write_manifest(paths: list[Path], out_path: Path) -> str:
    """Compute SHA-256 over each path and write a manifest file.

    The first line of the manifest is the SHA-256 of the manifest
    itself (after all other lines are written), so any post-hoc
    modification is detectable.

    Parameters
    ----------
    paths : list[Path]
        Files to hash. Order is preserved.
    out_path : Path
        Where to write the manifest. Will be overwritten if it exists.

    Returns
    -------
    str
        The SHA-256 of the manifest file itself (the seal).
    """
    lines: list[str] = []
    for p in paths:
        if p.is_file():
            digest = sha256_file(p)
        else:
            digest = "MISSING"
        lines.append(f"{digest}  {p.name}")
    body = "\n".join(lines) + "\n"
    # Write the body first, then seal it with its own hash
    out_path.write_text(body)
    seal = sha256_str(body)
    # Re-write with the seal line at the top
    final = f"{seal}  manifest.sha256\n{body}"
    out_path.write_text(final)
    return seal
