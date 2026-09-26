"""Semgrep adapter.

Wraps Semgrep as a one-shot process, reads its SARIF output, and normalizes each
result into a Finding. The SARIF parser is a pure function so it can be tested
without Semgrep installed (the deterministic engines ship as pinned containers in
production, but the normalization logic is what we own and must verify).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from trinetra.models.finding import EngineLayer, Finding, Location, Severity

_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _cwe_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        m = _CWE_RE.search(tag)
        if m:
            return m.group(0).upper()
    return None


def _rule_index(run: dict) -> dict[str, dict]:
    """Map ruleId -> rule metadata from the SARIF tool driver."""
    driver = run.get("tool", {}).get("driver", {})
    return {r.get("id"): r for r in driver.get("rules", []) if r.get("id")}


def parse_semgrep_sarif(sarif: dict, *, discipline: str = "web") -> list[Finding]:
    """Convert a Semgrep SARIF document into normalized Findings."""
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        rules = _rule_index(run)
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id, {})
            tags = rule.get("properties", {}).get("tags", []) or []
            message = result.get("message", {}).get("text", "") or rule_id or "Finding"

            loc = Location()
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                loc.file = phys.get("artifactLocation", {}).get("uri")
                loc.line = phys.get("region", {}).get("startLine")

            severity = _LEVEL_TO_SEVERITY.get(result.get("level", "warning"), Severity.MEDIUM)
            cwe = _cwe_from_tags(tags) or _cwe_from_tags([message])

            findings.append(
                Finding(
                    discipline=discipline,
                    source="semgrep",
                    engine_layer=EngineLayer.DETERMINISTIC,
                    title=(rule.get("shortDescription", {}).get("text") or message)[:200],
                    description=message,
                    severity=severity,
                    cwe=cwe,
                    rule_id=rule_id,
                    location=loc,
                    references=[u for u in [rule.get("helpUri")] if u],
                )
            )
    return findings


class SemgrepAdapter:
    name = "semgrep"
    disciplines = ["web", "api"]

    def __init__(self, config: str = "auto"):
        self.config = config

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, target: str, *, discipline: str = "web") -> list[Finding]:
        """Run `semgrep --sarif` against a source path and normalize the output."""
        if not self.available():
            raise RuntimeError(
                "semgrep is not installed. Install it (`pip install semgrep`) or run "
                "Trinetra with the pinned engine container."
            )
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["semgrep", "scan", "--sarif", "--quiet", "--config", self.config, str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if not proc.stdout.strip():
            raise RuntimeError(f"semgrep produced no output. stderr:\n{proc.stderr}")
        return parse_semgrep_sarif(json.loads(proc.stdout), discipline=discipline)

    def ingest_sarif(self, sarif_path: str | Path, *, discipline: str = "web") -> list[Finding]:
        """Normalize a pre-generated SARIF file (e.g. from a container run)."""
        data = json.loads(Path(sarif_path).read_text())
        return parse_semgrep_sarif(data, discipline=discipline)
