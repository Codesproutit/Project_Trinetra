"""Manual replay — fork a captured request, tweak it, re-run it.

A tester often wants to take a step the scanner made, change one thing (a header,
a payload) and fire it again. This models that fork purely: `fork()` returns a new
Step with overrides applied, leaving the original untouched. Actually sending it
is a thin live step (an injected HTTP client) kept out of the pure model so the
fork logic is testable without the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Step:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None


def fork(step: Step, *, body: str | None = None, headers: dict[str, str] | None = None) -> Step:
    """Return a copy of `step` with body/headers overridden (original unchanged)."""
    merged = {**step.headers, **(headers or {})}
    return replace(step, headers=merged, body=body if body is not None else step.body)


def send(step: Step, client) -> object:
    """Send a step with an injected HTTP client (e.g. httpx.Client). Live action."""
    return client.request(step.method, step.url, headers=step.headers, content=step.body)
