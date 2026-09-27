"""The AI cognitive reviewer.

The deterministic engines are precise about *patterns* but blind to *intent*: a
Semgrep hit on `subprocess(..., shell=True)` might be a real command injection or
a safe call on a constant string. The reviewer asks the LLM to make that call on
the items the dedup gate couldn't settle, then either drops a confirmed false
positive or enriches the finding (severity, exploitability note, remediation).

The provider is reached through the tiered `ProviderRouter`, so this code is
vendor-neutral and the router tracks tokens/cost. The LLM is asked for strict
JSON, and a reply that doesn't parse is treated as "uncertain" — the finding is
kept, never silently dropped, because dropping a real bug is the costly error.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from trinetra.models.finding import Finding, Severity
from trinetra.providers.router import ProviderRouter, Tier

logger = logging.getLogger(__name__)

_SYSTEM = (
    "You are a senior application security engineer triaging static-analysis "
    "findings for an AUTHORIZED penetration test. For each finding decide whether "
    "it is a true positive, and if so refine it. Reply with a single JSON object "
    "and nothing else."
)

_SCHEMA_HINT = (
    '{"verdict": "true_positive|false_positive|uncertain", '
    '"severity": "info|low|medium|high|critical", '
    '"rationale": "one sentence", "remediation": "one sentence"}'
)


@dataclass
class Verdict:
    verdict: str = "uncertain"
    severity: str | None = None
    rationale: str = ""
    remediation: str = ""

    @property
    def is_false_positive(self) -> bool:
        return self.verdict == "false_positive"


@dataclass
class ReviewOutcome:
    findings: list[Finding] = field(default_factory=list)  # kept (enriched) findings
    reviewed: int = 0
    dropped: int = 0  # confirmed false positives removed


def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of an LLM reply, tolerating code fences/prose."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object in reply")
    return json.loads(text[start : end + 1])


def parse_verdict(text: str) -> Verdict:
    try:
        data = _extract_json(text)
    except (ValueError, json.JSONDecodeError):
        logger.warning("AI reviewer reply did not parse; treating as uncertain")
        return Verdict()
    sev = str(data.get("severity", "")).lower()
    return Verdict(
        verdict=str(data.get("verdict", "uncertain")).lower(),
        severity=sev if sev in set(Severity) else None,
        rationale=str(data.get("rationale", "")),
        remediation=str(data.get("remediation", "")),
    )


def _prompt(f: Finding) -> str:
    loc = f.location
    where = loc.file or loc.route or "unknown"
    if loc.line:
        where = f"{where}:{loc.line}"
    return (
        f"Finding: {f.title}\n"
        f"Rule: {f.rule_id}  CWE: {f.cwe or 'n/a'}  Severity: {f.severity}\n"
        f"Location: {where}  Param: {loc.param or 'n/a'}\n"
        f"Description: {f.description or 'n/a'}\n\n"
        f"Is this exploitable in an authorized test? Reply as JSON: {_SCHEMA_HINT}"
    )


class AiReviewer:
    """Reviews the dedup gate's output through the provider router."""

    def __init__(self, router: ProviderRouter, *, tier: Tier = Tier.REVIEW):
        self.router = router
        self.tier = tier

    def available(self) -> bool:
        probe = getattr(self.router.provider, "available", None)
        return bool(probe()) if callable(probe) else True

    def _review_one(self, f: Finding) -> Verdict:
        completion = self.router.run(_prompt(f), tier=self.tier, system=_SYSTEM)
        return parse_verdict(completion.text)

    def review(self, findings: list[Finding]) -> ReviewOutcome:
        kept: list[Finding] = []
        dropped = 0
        for f in findings:
            verdict = self._review_one(f)
            if verdict.is_false_positive:
                dropped += 1
                continue
            enriched = f.model_copy(deep=True)
            if verdict.severity:
                enriched.severity = Severity(verdict.severity)
            if verdict.remediation and not enriched.remediation:
                enriched.remediation = verdict.remediation
            note = f"AI triage ({verdict.verdict}): {verdict.rationale}".strip()
            enriched.evidence.steps = [*f.evidence.steps, note]
            kept.append(enriched)
        return ReviewOutcome(findings=kept, reviewed=len(findings), dropped=dropped)
