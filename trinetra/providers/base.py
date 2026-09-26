"""The provider interface every LLM vendor adapter implements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class Completion:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    raw: dict = field(default_factory=dict)


@runtime_checkable
class LLMProvider(Protocol):
    name: str

    def complete(self, prompt: str, *, model: str, system: str | None = None) -> Completion:
        """Single-shot completion. Adapters own vendor-specific request shaping."""
        ...
