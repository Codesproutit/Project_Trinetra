"""Engine adapters — thin wrappers that normalize each tool's output to Finding."""

from trinetra.engines.base import EngineAdapter, EngineRegistry, registry

__all__ = ["EngineAdapter", "EngineRegistry", "registry"]
