"""SAST adapters."""

from trinetra.engines.sast.semgrep import SemgrepAdapter, parse_semgrep_sarif

__all__ = ["SemgrepAdapter", "parse_semgrep_sarif"]
