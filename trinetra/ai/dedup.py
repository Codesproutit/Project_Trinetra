"""Strict dedup / triage gate for the AI cognitive pass.

The AI pass is the expensive step, so it must never re-review something the
deterministic engines already settled. This gate selects only the findings worth
an LLM look: still THEORETICAL (not dynamically confirmed), from a deterministic
engine, and severe enough to matter. Everything the pipeline already confirmed —
including IAST-upgraded findings — is skipped.

Pure and deterministic: no LLM call here, so it is cheap and fully testable.
"""

from __future__ import annotations

from trinetra.models.finding import Confidence, EngineLayer, Finding, Severity


def needs_review(
    findings: list[Finding], *, min_severity: Severity = Severity.MEDIUM
) -> list[Finding]:
    """Return the deterministic, still-theoretical findings worth an AI review."""
    order = list(Severity)
    floor = order.index(min_severity)
    return [
        f
        for f in findings
        if f.confidence == Confidence.THEORETICAL
        and f.engine_layer == EngineLayer.DETERMINISTIC
        and order.index(f.severity) >= floor
    ]
