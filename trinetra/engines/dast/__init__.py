"""DAST adapters — dynamic scanning of a running target (API + Web)."""

from trinetra.engines.dast.nuclei import NucleiAdapter, parse_nuclei_jsonl
from trinetra.engines.dast.zap import ZapAdapter, parse_zap_alerts

__all__ = ["NucleiAdapter", "parse_nuclei_jsonl", "ZapAdapter", "parse_zap_alerts"]
