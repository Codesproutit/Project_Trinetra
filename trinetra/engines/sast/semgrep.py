"""Semgrep adapter.

Wraps Semgrep as a one-shot process, reads its SARIF output, and normalizes each
result into a Finding. The SARIF parser is a pure function so it can be tested
without Semgrep installed (the deterministic engines ship as pinned containers in
production, but the normalization logic is what we own and must verify).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from trinetra.models.finding import EngineLayer, Finding, Location, Severity
from trinetra.models.rule import Rule
from trinetra.rules import BUNDLED_RULES_DIR

logger = logging.getLogger(__name__)

# `--config` value that selects Trinetra's own offline ruleset (trinetra/rules/).
BUNDLED = "bundled"

# Semgrep exit codes: 0 = clean, 1 = findings (with --error). Anything else is a
# real failure (bad rule, bad target, crash) and must not look like "no findings".
_OK_EXIT_CODES = {0, 1}

# A bare (dotted) identifier, e.g. "python.lang.sqli" or "40018": a rule-id seed,
# not a structural Semgrep pattern.
_SEED_ONLY_RE = re.compile(r"^[\w.\-]+$")

_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_OWASP_RE = re.compile(r"A\d{2}:\d{4}(?: - [^,]+)?")


def _cwe_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        m = _CWE_RE.search(tag)
        if m:
            return m.group(0).upper()
    return None


def _owasp_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        if tag.upper().startswith("OWASP"):
            m = _OWASP_RE.search(tag)
            if m:
                return m.group(0).strip()
    return None


def _headline(message: str) -> str:
    """The lead phrase of a rule message ("SQL injection: ..." -> "SQL injection").

    Messages are written headline-first, so the title stays short and scannable
    while the full message remains the description.
    """
    text = " ".join(message.split())
    head, sep, _ = text.partition(": ")
    if sep and len(head) <= 60:
        return head
    sentence, sep, _ = text.partition(". ")
    return sentence.rstrip(".") if sep and len(sentence) <= 80 else text


def _resolve_severity(result: dict, rule: dict) -> Severity:
    """Resolve severity as faithfully as Semgrep's SARIF allows.

    Semgrep collapses rule severity onto a coarse SARIF `level` (an ERROR rule can
    surface as "warning"), so prefer its CVSS-style `security-severity` property
    (present on registry rules) when available; otherwise fall back to the level,
    then to the rule's default configuration.
    """
    raw = (rule.get("properties", {}) or {}).get("security-severity")
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            if score > 0:
                return Severity.LOW
            return Severity.INFO
    level = (
        result.get("level")
        or rule.get("defaultConfiguration", {}).get("level")
        or "warning"
    )
    return _LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM)


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

            severity = _resolve_severity(result, rule)
            cwe = _cwe_from_tags(tags) or _cwe_from_tags([message])

            # Semgrep sets shortDescription to boilerplate ("Semgrep Finding: <id>")
            # for local rules; prefer the human-written message in that case.
            short = rule.get("shortDescription", {}).get("text")
            if not short or short.startswith("Semgrep Finding"):
                short = _headline(message)
            title = " ".join(short.split())[:200]  # collapse whitespace/newlines

            findings.append(
                Finding(
                    discipline=discipline,
                    source="semgrep",
                    engine_layer=EngineLayer.DETERMINISTIC,
                    title=title,
                    description=message,
                    severity=severity,
                    cwe=cwe,
                    owasp=_owasp_from_tags(tags),
                    rule_id=rule_id,
                    location=loc,
                    references=[u for u in [rule.get("helpUri")] if u],
                )
            )
    return findings


def resolve_configs(configs: list[str] | str | None) -> list[str]:
    """Expand the `bundled` keyword to the shipped ruleset directory."""
    if configs is None:
        configs = [BUNDLED]
    elif isinstance(configs, str):
        configs = [configs]
    return [str(BUNDLED_RULES_DIR) if c == BUNDLED else c for c in configs]


def build_command(configs: list[str], target: str, binary: str = "semgrep") -> list[str]:
    """Build the semgrep argv. Pure, so it is testable without semgrep installed."""
    argv = [binary, "scan", "--sarif", "--quiet", "--disable-version-check"]
    # The registry's "auto" config requires metrics; everything else runs with
    # metrics off so no scan metadata leaves the machine.
    if "auto" not in configs:
        argv.append("--metrics=off")
    for c in configs:
        argv += ["--config", c]
    argv.append(str(target))
    return argv


def learned_rules_document(rules: list[Rule]) -> dict | None:
    """Render brain rules as one Semgrep config document, skipping unrunnable ones.

    A learned rule without a language or pattern cannot run; including it would make
    Semgrep reject the whole config, so it is dropped here with a log line.
    """
    rendered = []
    for rule in rules:
        if not rule.pattern or not rule.languages:
            logger.warning("Skipping learned rule %s: no pattern/languages", rule.id)
            continue
        if _SEED_ONLY_RE.match(rule.pattern):
            # synthesize() seeds `pattern` with the origin rule id until the AI pass
            # refines it; as code that would match any identifier of that name.
            logger.warning("Skipping learned rule %s: pattern is an unrefined seed", rule.id)
            continue
        rendered.append(rule.to_semgrep())
    return {"rules": rendered} if rendered else None


class SemgrepAdapter:
    name = "semgrep"
    disciplines = ["web", "api"]
    input_kind = "source"

    def __init__(
        self,
        configs: list[str] | str | None = None,
        *,
        learned_rules: dict[str, list[Rule]] | None = None,
        config: str | None = None,
    ):
        # `config` is the original single-value keyword, kept for compatibility.
        self.configs = resolve_configs(configs if configs is not None else config)
        # discipline -> rules promoted into that discipline's brain by the learner.
        self.learned_rules = learned_rules or {}

    @property
    def config(self) -> str:
        return ",".join(self.configs)

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def _run(self, configs: list[str], target: str) -> dict:
        env = {**os.environ, "PYTHONUTF8": "1"}  # Semgrep's CLI crashes on cp1252 consoles
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            build_command(configs, target),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            check=False,
        )
        if proc.returncode not in _OK_EXIT_CODES or not proc.stdout.strip():
            raise RuntimeError(
                f"semgrep failed (exit {proc.returncode}). stderr:\n{proc.stderr[-2000:]}"
            )
        return json.loads(proc.stdout)

    def scan(self, target: str, *, discipline: str = "web") -> list[Finding]:
        """Run `semgrep --sarif` against a source path and normalize the output.

        The base rulesets run first. Rules the learner promoted into this
        discipline's brain run in a second, separate pass, so a bad learned rule
        can never take down the base scan.
        """
        if not self.available():
            raise RuntimeError(
                "semgrep is not installed. Install it (`pip install semgrep`) or run "
                "Trinetra with the pinned engine container."
            )
        findings = parse_semgrep_sarif(self._run(self.configs, target), discipline=discipline)

        doc = learned_rules_document(self.learned_rules.get(discipline, []))
        if doc is not None:
            with tempfile.TemporaryDirectory() as td:
                rule_file = Path(td) / "learned.yaml"
                rule_file.write_text(json.dumps(doc), encoding="utf-8")  # JSON is valid YAML
                try:
                    sarif = self._run([str(rule_file)], target)
                    findings += parse_semgrep_sarif(sarif, discipline=discipline)
                except (RuntimeError, json.JSONDecodeError):
                    logger.exception("Learned %s rules failed; base results kept", discipline)
        return findings

    def ingest_sarif(self, sarif_path: str | Path, *, discipline: str = "web") -> list[Finding]:
        """Normalize a pre-generated SARIF file (e.g. from a container run)."""
        data = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        return parse_semgrep_sarif(data, discipline=discipline)
