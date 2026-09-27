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

    def all(self) -> list[EngineAdapter]:
        return list(self._engines.values())


registry = EngineRegistry()
