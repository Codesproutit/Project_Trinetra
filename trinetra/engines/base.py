"""The adapter contract every wrapped engine implements.

A new engine is one new adapter class registered here; nothing else in the
platform changes. That is what keeps "wrap, don't rebuild" cheap and swappable.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from trinetra.models.finding import Finding


@runtime_checkable
class EngineAdapter(Protocol):
    name: str
    disciplines: list[str]
    # "source" engines take a local path (SAST/SCA); "target" engines take a URL
    # (DAST). The pipeline routes by this so a URL scan never invokes a SAST engine.
    input_kind: str

    def available(self) -> bool:
        """True if this engine can actually run here (binary/daemon present)."""
        ...

    def scan(self, target: str, *, discipline: str) -> list[Finding]:
        """Run the engine against a target and return normalized findings."""
        ...


class EngineRegistry:
    def __init__(self) -> None:
        self._engines: dict[str, EngineAdapter] = {}

    def register(self, engine: EngineAdapter) -> None:
        self._engines[engine.name] = engine

    def get(self, name: str) -> EngineAdapter:
        return self._engines[name]

    def for_discipline(self, discipline: str) -> list[EngineAdapter]:
        return [e for e in self._engines.values() if discipline in e.disciplines]

    def select(self, discipline: str, input_kind: str) -> list[EngineAdapter]:
        return [
            e
            for e in self._engines.values()
            if discipline in e.disciplines and getattr(e, "input_kind", "source") == input_kind
        ]

    def all(self) -> list[EngineAdapter]:
        return list(self._engines.values())


registry = EngineRegistry()
