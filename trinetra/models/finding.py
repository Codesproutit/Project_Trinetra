"""The Finding schema — the common language for every engine and the AI layer.

Every adapter normalizes its native output into a Finding. Strict dedup keys off
`fingerprint`, so the AI pass never re-reviews something the deterministic engines
already settled.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Theoretical until dynamic reachability confirms it (see hybrid/confirm)."""

    THEORETICAL = "theoretical"
    CONFIRMED = "confirmed"


class EngineLayer(StrEnum):
    DETERMINISTIC = "deterministic"
    AI = "ai"


# SARIF maps only 3 levels; we collapse severity onto them for the report layer.
_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


class Location(BaseModel):
    """Where the finding lives. Fields are optional per discipline (code vs. HTTP)."""

    file: str | None = None
    line: int | None = None
    route: str | None = None
    param: str | None = None


class Evidence(BaseModel):
    """Chain-of-custody material that makes a finding defensible in an audit."""

    request: str | None = None
    response: str | None = None
    oast_token: str | None = None
    steps: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    discipline: str  # "web" | "api" | "android" | "desktop" | "infra"
    source: str  # "semgrep" | "sca" | "zap" | "ai_reviewer" | ...
    engine_layer: EngineLayer = EngineLayer.DETERMINISTIC
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.THEORETICAL
    cwe: str | None = None
    owasp: str | None = None
    rule_id: str | None = None
    location: Location = Field(default_factory=Location)
    evidence: Evidence = Field(default_factory=Evidence)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    @property
    def sarif_level(self) -> str:
        return _SARIF_LEVEL[self.severity]

    @property
    def fingerprint(self) -> str:
        """Stable dedup key.

        Built from the identity of the finding (what + where), never from volatile
        fields like description, so the same issue from two engines collapses to one
        key and the AI pass can skip anything already settled.
        """

        parts = [
            self.discipline,
            (self.rule_id or self.title).strip().lower(),
            self.cwe or "",
            self.location.file or self.location.route or "",
            str(self.location.line or ""),
            self.location.param or "",
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()
