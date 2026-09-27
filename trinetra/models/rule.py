"""The Rule schema — a detection rule owned by a discipline brain.

A rule is what the learner synthesizes from a novel confirmed finding and what the
sandbox validator gates before it joins a brain. It is stored engine-neutrally
(as JSON in the brain) and exported to a Semgrep rule when an engine needs to run
it, so the store carries no third-party dependency.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from trinetra.models.finding import Severity


class Rule(BaseModel):
    id: str
    discipline: str  # which brain owns it
    languages: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cwe: str | None = None
    pattern: str | None = None  # Semgrep-style pattern (may be refined by the AI)
    source: str = "learner"
    metadata: dict = Field(default_factory=dict)

    def to_semgrep(self) -> dict:
        """Render as a Semgrep rule dict (for an engine that will run it)."""
        rule: dict = {
            "id": self.id,
            "severity": {"info": "INFO", "low": "WARNING", "medium": "WARNING",
                         "high": "ERROR", "critical": "ERROR"}[self.severity],
            "message": self.metadata.get("message", self.id),
            "metadata": {"cwe": self.cwe, "source": self.source, **self.metadata},
        }
        if self.languages:
            rule["languages"] = self.languages
        if self.pattern:
            rule["pattern"] = self.pattern
        return rule
