"""Evidence chain-of-custody.

A finding is only defensible in an audit if its evidence is tamper-evident. For
each finding we capture the request/response, any OAST token, and the exact steps,
then hash the canonical record with SHA-256. The hash is what a report cites and
what a reviewer can re-verify: change any evidence field and the hash changes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from trinetra.models.finding import Finding


@dataclass
class EvidenceRecord:
    fingerprint: str
    title: str
    sha256: str
    request: str | None = None
    response: str | None = None
    oast_token: str | None = None
    steps: list[str] = field(default_factory=list)


def _canonical(finding: Finding) -> str:
    ev = finding.evidence
    payload = {
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "cwe": finding.cwe,
        "severity": str(finding.severity),
        "request": ev.request,
        "response": ev.response,
        "oast_token": ev.oast_token,
        "steps": ev.steps,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def evidence_for(finding: Finding) -> EvidenceRecord:
    digest = hashlib.sha256(_canonical(finding).encode()).hexdigest()
    ev = finding.evidence
    return EvidenceRecord(
        fingerprint=finding.fingerprint,
        title=finding.title,
        sha256=digest,
        request=ev.request,
        response=ev.response,
        oast_token=ev.oast_token,
        steps=list(ev.steps),
    )


def attach_evidence(findings: list[Finding]) -> dict[str, EvidenceRecord]:
    """Return an evidence record per finding, keyed by fingerprint."""
    return {f.fingerprint: evidence_for(f) for f in findings}
