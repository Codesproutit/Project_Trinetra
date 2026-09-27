"""Turn a novel confirmed finding into a candidate detection rule.

The MVP synthesis is deterministic and structural: it derives a stable rule id
and metadata from the finding's identity and carries the finding's Semgrep rule id
as the pattern seed. The AI reviewer refines the pattern into a generic structural
matcher in a later increment; this keeps the loop runnable and testable without an
LLM. Nothing here promotes a rule — that only happens after the sandbox gate.
"""

from __future__ import annotations

import re

from trinetra.models.finding import Finding
from trinetra.models.rule import Rule

_LANG_BY_DISCIPLINE = {
    "web": ["python", "javascript"],
    "api": ["python", "javascript"],
    "android": ["java", "kotlin"],
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48] or "rule"


def synthesize(finding: Finding) -> Rule:
    """Build a candidate Rule from a confirmed finding (does not promote it)."""
    slug = _slug(finding.rule_id or finding.title)
    return Rule(
        id=f"trinetra.{finding.discipline}.learned.{slug}",
        discipline=finding.discipline,
        languages=_LANG_BY_DISCIPLINE.get(finding.discipline, []),
        severity=finding.severity,
        cwe=finding.cwe,
        pattern=finding.rule_id,  # seed; refined by the AI pass later
        source="learner",
        metadata={
            "message": finding.title,
            "origin_fingerprint": finding.fingerprint,
            "origin_source": finding.source,
        },
    )
