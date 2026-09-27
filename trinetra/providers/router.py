"""Tiered provider router.

Picks a cost tier per task and tracks token spend. Phase 1 only constructs it and
resolves model IDs; the AI cognitive pass wires it into the scan flow later.
"""

from __future__ import annotations

from enum import StrEnum

from trinetra.config import Settings, load_settings
from trinetra.providers.base import Completion, LLMProvider


class Tier(StrEnum):
    TRIAGE = "triage"  # cheap: cluster + dedup filtering
    REVIEW = "review"  # most code / API review
    REASONING = "reasoning"  # hard multi-file taint, logic flaws


class ProviderRouter:
    def __init__(self, provider: LLMProvider, settings: Settings | None = None):
        self.provider = provider
        self.settings = settings or load_settings()
        self.input_tokens = 0
        self.output_tokens = 0

    def model_for(self, tier: Tier) -> str:
        return {
            Tier.TRIAGE: self.settings.models.triage,
            Tier.REVIEW: self.settings.models.review,
            Tier.REASONING: self.settings.models.reasoning,
        }[tier]

    def run(self, prompt: str, *, tier: Tier, system: str | None = None) -> Completion:
        result = self.provider.complete(prompt, model=self.model_for(tier), system=system)
        self.input_tokens += result.input_tokens
        self.output_tokens += result.output_tokens
        return result
