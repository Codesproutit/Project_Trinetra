"""Nuclei adapter.

Runs Nuclei (template-based dynamic checks) against a URL and normalizes its
JSONL output to Finding. Nuclei ships as a pinned container/binary; the adapter
degrades gracefully when it isn't present. The JSONL parser is pure and tested
without the binary.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from trinetra.models.finding import Confidence, EngineLayer, Finding, Location, Severity

logger = logging.getLogger(__name__)

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _cwe_from_classification(info: dict) -> str | None:
    cwes = (info.get("classification", {}) or {}).get("cwe-id") or []
    if cwes:
        c = str(cwes[0]).upper()
        return c if c.startswith("CWE-") else f"CWE-{c.removeprefix('CWE-')}"
    return None


def parse_nuclei_jsonl(text: str, *, discipline: str) -> list[Finding]:
    """Parse Nuclei's `-jsonl` output (one JSON object per line)."""
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping non-JSON nuclei line")
            continue
        info = row.get("info", {}) or {}
        findings.append(
            Finding(
                discipline=discipline,
                source="nuclei",
                engine_layer=EngineLayer.DETERMINISTIC,
                title=info.get("name") or row.get("template-id") or "Nuclei match",
                description=info.get("description", ""),
                severity=_SEVERITY.get((info.get("severity") or "info").lower(), Severity.INFO),
                confidence=Confidence.CONFIRMED,  # nuclei matched against a live target
                cwe=_cwe_from_classification(info),
                rule_id=row.get("template-id"),
                location=Location(route=row.get("matched-at") or row.get("host")),
                references=info.get("reference") or [],
            )
        )
    return findings


class NucleiAdapter:
    name = "nuclei"
    disciplines = ["web", "api"]
    input_kind = "target"

    def __init__(self, binary: str = "nuclei"):
        self.binary = binary

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, target: str, *, discipline: str = "web") -> list[Finding]:
        if not self.available():
            raise RuntimeError(
                "nuclei is not installed. Install it or run Trinetra with the pinned "
                "engine container."
            )
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [self.binary, "-u", target, "-jsonl", "-silent"],
            capture_output=True,
            text=True,
            check=False,
        )
        return parse_nuclei_jsonl(proc.stdout, discipline=discipline)
