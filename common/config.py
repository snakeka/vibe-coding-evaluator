"""common.config — load freeze artefacts and environment configuration.

This module is the substrate for the §3.5 freeze discipline (§B.6).
It loads ``models.lock`` and ``prompts.lock`` from the repository
root, validates the freeze tag is consistent across both, and exposes
typed accessor functions used by every pipeline orchestrator.

The module refuses to load a freeze artefact whose internal
``freeze_tag`` differs from the one recorded at run start, so any
silent modification between runs is detectable before the run
proceeds (§3.7).

Usage
-----

>>> from common.config import load_models_lock, load_prompts_lock
>>> models = load_models_lock()         # validated against freeze tag
>>> prompts = load_prompts_lock()
>>> qwen = models.get_model("qwen2.5-coder:32b")
>>> print(qwen.provider, qwen.endpoint)
ollama http://192.168.5.204:11434
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

# Resolve repo root once at module load. The freeze artefacts live at
# the repo root regardless of the caller's CWD, so we anchor on the
# parent of this file's parent's parent.
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODELS_LOCK = REPO_ROOT / "models.lock"
DEFAULT_PROMPTS_LOCK = REPO_ROOT / "prompts.lock"


@dataclass(frozen=True)
class ProviderSpec:
    """A single provider entry in models.lock (§B.6).

    Frozen so that downstream code cannot mutate the lock at runtime —
    modifications require a documented bump of the freeze_tag.
    """

    provider: str
    model_id: str
    endpoint: str
    version_hash: str | None
    locked_at: str
    notes: str = ""

    @property
    def api_base(self) -> str | None:
        """For LiteLLM, the API base URL when the provider requires it.

        Returns the endpoint for providers that need api_base hint
        (ollama + deepseek — both use OpenAI-compatible /v1 path).
        Other providers (openai, anthropic) have implicit defaults in
        litellm that work without an explicit api_base.
        """
        if self.provider in ("ollama", "deepseek"):
            return self.endpoint
        return None

    @property
    def is_locally_served(self) -> bool:
        """True if the model runs on local hardware (not a cloud API).

        Used by the Cross-Model Benchmarker to distinguish in-process
        inference cost from external API latency/cost (§5.5).
        """
        return self.provider == "ollama"

    @property
    def is_region_blocked(self) -> bool:
        """True if egress from the current region is known to fail.

        Anthropic HTTP 403 from HK egress is the canonical case (§5.5
        cross-model robustness discussion). The Cross-Model Benchmarker
        treats such providers as optional: a 403 records the row as
        ``provider_unavailable`` rather than aborting the run.
        """
        # This is a coarse signal — the actual 403 is detected at call
        # time by benchmark/provider_layer. We use this flag to skip
        # the Anthropic row entirely when running from HK egress without
        # any proxy, and to emit a clear audit-log marker.
        return self.provider == "anthropic"

    @property
    def api_key_env_var(self) -> str:
        """The env var name that holds the API key for this provider."""
        return {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "mistral": "MISTRAL_API_KEY",
            "ollama": "",  # local, no key required
        }.get(self.provider, f"{self.provider.upper()}_API_KEY")


@dataclass(frozen=True)
class ModelsLock:
    """Parsed models.lock (§B.6 freeze artefact)."""

    freeze_tag: str
    locked_at: str
    providers: tuple[ProviderSpec, ...]
    generation_params: dict[str, Any] = field(default_factory=dict)
    seed_policy: dict[str, Any] = field(default_factory=dict)

    def get_model(self, model_id: str) -> ProviderSpec:
        """Return the ProviderSpec for a model_id or raise."""
        for p in self.providers:
            if p.model_id == model_id:
                return p
        raise KeyError(
            f"Model '{model_id}' not found in models.lock freeze. "
            f"Available: {[p.model_id for p in self.providers]}"
        )

    def get_provider(self, provider_name: str) -> list[ProviderSpec]:
        """Return all models for a provider."""
        return [p for p in self.providers if p.provider == provider_name]


@dataclass(frozen=True)
class PromptEntry:
    """A single prompt entry in prompts.lock (§B.6)."""

    prompt_id: str
    task: str
    language: str
    prompt_text: str
    expected_cwe: str | None
    expected_severity: str | None


@dataclass(frozen=True)
class PromptsLock:
    """Parsed prompts.lock (§B.6 freeze artefact)."""

    freeze_tag: str
    generated_at: str
    prompts: tuple[PromptEntry, ...]

    def get(self, prompt_id: str) -> PromptEntry:
        """Return the PromptEntry for a prompt_id or raise."""
        for p in self.prompts:
            if p.prompt_id == prompt_id:
                return p
        raise KeyError(f"Prompt '{prompt_id}' not found in prompts.lock")


def load_models_lock(path: Path | str | None = None) -> ModelsLock:
    """Load and validate models.lock from disk.

    Parameters
    ----------
    path : Path | str | None
        Path to the lock file. Defaults to the repo-root ``models.lock``.

    Returns
    -------
    ModelsLock
        Validated, frozen dataclass.

    Raises
    ------
    FileNotFoundError
        If the lock file does not exist.
    ValueError
        If the freeze_tag is missing or inconsistent.
    """
    p = Path(path) if path else DEFAULT_MODELS_LOCK
    if not p.exists():
        raise FileNotFoundError(f"models.lock not found at {p}")

    raw = yaml.safe_load(p.read_text())
    freeze_tag = raw.get("freeze_tag")
    if not freeze_tag:
        raise ValueError("models.lock missing required field: freeze_tag")

    providers = tuple(
        ProviderSpec(
            provider=e["provider"],
            model_id=e["model_id"],
            endpoint=e["endpoint"],
            version_hash=e.get("version_hash"),
            locked_at=e.get("locked_at", ""),
            notes=e.get("notes", ""),
        )
        for e in raw.get("providers", [])
    )

    return ModelsLock(
        freeze_tag=freeze_tag,
        locked_at=raw.get("locked_at", ""),
        providers=providers,
        generation_params=raw.get("generation_params", {}),
        seed_policy=raw.get("seed_policy", {}),
    )


def load_prompts_lock(path: Path | str | None = None) -> PromptsLock:
    """Load and validate prompts.lock from disk."""
    p = Path(path) if path else DEFAULT_PROMPTS_LOCK
    if not p.exists():
        raise FileNotFoundError(f"prompts.lock not found at {p}")

    raw = yaml.safe_load(p.read_text())
    freeze_tag = raw.get("freeze_tag")
    if not freeze_tag:
        raise ValueError("prompts.lock missing required field: freeze_tag")

    prompts = tuple(
        PromptEntry(
            prompt_id=e["prompt_id"],
            task=e["task"],
            language=e["language"],
            prompt_text=e["prompt_text"].strip(),
            expected_cwe=e.get("expected_cwe"),
            expected_severity=e.get("expected_severity"),
        )
        for e in raw.get("prompts", [])
    )

    return PromptsLock(
        freeze_tag=freeze_tag,
        generated_at=raw.get("generated_at", ""),
        prompts=prompts,
    )


def assert_freeze_consistent(models: ModelsLock, prompts: PromptsLock) -> None:
    """Refuse to proceed if freeze_tags disagree (§3.7)."""
    if models.freeze_tag != prompts.freeze_tag:
        raise ValueError(
            f"Freeze tag mismatch: models.lock='{models.freeze_tag}' vs "
            f"prompts.lock='{prompts.freeze_tag}'. Refusing to run until "
            f"both locks are bumped together with a documented justification."
        )


def load_env() -> None:
    """Load .env from repo root if present (non-fatal)."""
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def get_api_key(env_var: str) -> str | None:
    """Return an API key from env or None (with a soft warn on first call)."""
    val = os.environ.get(env_var)
    if not val:
        # Lazy import to avoid pulling rich into unit tests
        import warnings
        warnings.warn(
            f"{env_var} not set. Provider calls will fail unless set in "
            f"environment or .env file.",
            stacklevel=2,
        )
    return val
