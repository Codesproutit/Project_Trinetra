"""Runtime configuration.

Model IDs live here as defaults only. They are runtime-switchable via environment
variables so an operator can change the reasoning engine without touching code:

    TRINETRA_MODEL_REASONING=claude-opus-5-5 trinetra scan ...
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ModelTiers:
    """Three cost tiers for the AI cognitive layer (Phase 4 wires these in).

    Defaults are current Anthropic API model IDs. The top tier defaults to the
    stable Opus 5; switch to a newer Opus by overriding TRINETRA_MODEL_REASONING.
    """

    triage: str = os.getenv("TRINETRA_MODEL_TRIAGE", "claude-haiku-4-5")
    review: str = os.getenv("TRINETRA_MODEL_REVIEW", "claude-sonnet-5")
    reasoning: str = os.getenv("TRINETRA_MODEL_REASONING", "claude-opus-5")


@dataclass(frozen=True)
class Settings:
    """Global settings resolved from the environment with sane defaults."""

    provider: str = os.getenv("TRINETRA_PROVIDER", "anthropic")
    models: ModelTiers = field(default_factory=ModelTiers)
    # Where a scan run's artifacts (findings, SARIF, evidence) are written.
    run_dir: Path = Path(os.getenv("TRINETRA_RUN_DIR", ".trinetra/runs"))
    # Default per-host request ceiling so a scan can never overwhelm a target.
    default_rps: float = float(os.getenv("TRINETRA_DEFAULT_RPS", "10"))


def load_settings() -> Settings:
    return Settings()
