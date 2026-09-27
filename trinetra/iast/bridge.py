"""The IAST bridge — static taint → dynamic confirmation.

SAST (Phase 1) finds *candidate* sinks: a SQL string built from input, a
subprocess call, a URL fetched from a parameter. Each is real code, but static
analysis can't prove it's *reachable and exploitable* at runtime — so it ships as
THEORETICAL. DAST/OAST (Phase 2) proves things dynamically, but scans blind.

This bridge connects the two:

  1. `derive_tasks(...)` turns each injectable static finding into a
     VerificationTask — a prioritized item for the DAST queue, tagged with the
     vulnerability class to probe. Blind classes (SSRF, blind RCE/SQLi) get an
     OAST callback minted so an out-of-band hit ties straight back to the sink.
  2. `correlate(...)` matches dynamic CONFIRMED findings back to the static
     candidates. A static sink whose class the dynamic scan confirmed is upgraded
     THEORETICAL → CONFIRMED, with the dynamic evidence stapled on. That is the
     IAST result: a code location *and* runtime proof, in one finding.

Pure functions, no network — the whole bridge is unit-tested without a live
target.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from trinetra.engines.oast import OastListener
from trinetra.models.finding import Confidence, Finding

# CWE -> (vulnerability class, verifiable out-of-band?). Only classes a dynamic
# probe can meaningfully confirm are listed; anything else stays SAST-only.
_CWE_CLASS: dict[str, tuple[str, bool]] = {
    "CWE-89": ("sql_injection", True),  # blind SQLi -> timing/OAST
    "CWE-78": ("command_injection", True),  # blind RCE -> OAST callback
    "CWE-94": ("code_injection", True),
    "CWE-918": ("ssrf", True),  # SSRF is the canonical OAST case
    "CWE-611": ("xxe", True),
    "CWE-79": ("xss", False),  # reflected/stored, not out-of-band
    "CWE-22": ("path_traversal", False),
    "CWE-90": ("ldap_injection", False),
    "CWE-98": ("file_inclusion", False),
}


def vuln_class(cwe: str | None) -> str | None:
    """Map a CWE id to the bridge's vulnerability class, or None if not bridgeable."""
    if not cwe:
        return None
    entry = _CWE_CLASS.get(cwe.strip().upper())
    return entry[0] if entry else None


def _is_blind(cwe: str | None) -> bool:
    entry = _CWE_CLASS.get((cwe or "").strip().upper())
    return bool(entry and entry[1])


@dataclass
class VerificationTask:
    """A static sink queued for dynamic verification."""

    source_fingerprint: str  # the static Finding this came from
    vuln_class: str
    cwe: str | None
    discipline: str
    file: str | None = None
    line: int | None = None
    route: str | None = None
    param: str | None = None
    blind: bool = False  # verifiable via an out-of-band callback
    oast_token: str | None = None  # set once an OAST callback is minted

    @property
    def node_id(self) -> str:
        """A stable label for the injection point, used for OAST correlation."""
        where = self.route or (f"{self.file}:{self.line}" if self.file else "unknown")
        return f"{self.vuln_class}@{where}"


def _is_static_candidate(f: Finding) -> bool:
    # A static sink: deterministic engine, not yet dynamically proven.
    return f.confidence == Confidence.THEORETICAL and f.source not in {"zap", "nuclei", "oast"}


def derive_tasks(static_findings: list[Finding]) -> list[VerificationTask]:
    """Turn injectable static findings into a prioritized DAST verification queue."""
    tasks: list[VerificationTask] = []
    for f in static_findings:
        if not _is_static_candidate(f):
            continue
        klass = vuln_class(f.cwe)
        if klass is None:
            continue
        tasks.append(
            VerificationTask(
                source_fingerprint=f.fingerprint,
                vuln_class=klass,
                cwe=f.cwe,
                discipline=f.discipline,
                file=f.location.file,
                line=f.location.line,
                route=f.location.route,
                param=f.location.param,
                blind=_is_blind(f.cwe),
            )
        )
    return tasks


def mint_oast_callbacks(tasks: list[VerificationTask], listener: OastListener) -> None:
    """For each blind task, mint a callback host tied to the task's node.

    An out-of-band hit on that host later correlates through the OAST listener
    back to this exact sink. Mutates each blind task's `oast_token` in place.
    """
    if not listener.available():
        return
    for task in tasks:
        if task.blind:
            token, _host = listener.new_callback(task.node_id)
            task.oast_token = token


@dataclass
class CorrelationResult:
    findings: list[Finding]  # static findings, with confirmed ones upgraded
    confirmed_count: int = 0
    task_count: int = 0
    matched_fingerprints: set[str] = field(default_factory=set)


def _dynamic_confirmed_classes(dynamic_findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group dynamically-CONFIRMED findings by (discipline, vuln_class)."""
    grouped: dict[str, list[Finding]] = {}
    for f in dynamic_findings:
        if f.confidence != Confidence.CONFIRMED:
            continue
        klass = vuln_class(f.cwe)
        if klass is None:
            continue
        grouped.setdefault(f"{f.discipline}:{klass}", []).append(f)
    return grouped


def _matches(static: Finding, dynamic: Finding) -> bool:
    # If both name a parameter, they must agree; otherwise class + discipline is
    # the join (a static SQLi sink + a dynamically confirmed SQLi on the target).
    sp, dp = static.location.param, dynamic.location.param
    if sp and dp:
        return sp == dp
    return True


def correlate(
    static_findings: list[Finding],
    dynamic_findings: list[Finding],
    *,
    tasks: list[VerificationTask] | None = None,
) -> CorrelationResult:
    """Upgrade static candidates that the dynamic scan confirmed.

    Returns the static findings with matched ones promoted to CONFIRMED and the
    dynamic evidence attached. Dynamic findings themselves are returned unchanged
    by the pipeline alongside these.
    """
    grouped = _dynamic_confirmed_classes(dynamic_findings)
    out: list[Finding] = []
    matched: set[str] = set()
    for f in static_findings:
        klass = vuln_class(f.cwe)
        candidates = grouped.get(f"{f.discipline}:{klass}", []) if klass else []
        hit = next((d for d in candidates if _matches(f, d)), None)
        if hit is None or f.confidence == Confidence.CONFIRMED:
            out.append(f)
            continue
        upgraded = f.model_copy(deep=True)
        upgraded.confidence = Confidence.CONFIRMED
        note = (
            f"IAST: dynamically confirmed by {hit.source} at "
            f"{hit.location.route or 'target'} (same {klass})."
        )
        upgraded.evidence.steps = [*f.evidence.steps, note]
        if hit.evidence.oast_token and not upgraded.evidence.oast_token:
            upgraded.evidence.oast_token = hit.evidence.oast_token
        out.append(upgraded)
        matched.add(f.fingerprint)
    return CorrelationResult(
        findings=out,
        confirmed_count=len(matched),
        task_count=len(tasks or []),
        matched_fingerprints=matched,
    )
