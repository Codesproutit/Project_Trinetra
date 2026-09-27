"""OAST listener (Interactsh-style).

Generates a unique callback host per test node, then polls an interaction server
for hits. A received DNS/HTTP/HTTPS callback proves a blind vulnerability (blind
SSRF, blind RCE, blind SQLi) at the node that injected the token — so a correlated
interaction becomes a CONFIRMED finding.

The interaction server is pluggable behind OastBackend. NullOastBackend is used
when none is configured (poll returns nothing); a real Interactsh client
implements the same protocol. This keeps the correlation logic testable without
a live server.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from trinetra.models.finding import Confidence, EngineLayer, Evidence, Finding, Location, Severity


@dataclass
class Interaction:
    """A single callback received by the interaction server."""

    token: str  # the correlation token seen in the callback host
    protocol: str  # "dns" | "http" | "https" | "smtp" ...
    remote_addr: str = ""
    raw: str = ""
    timestamp: str = ""


@runtime_checkable
class OastBackend(Protocol):
    domain: str

    def register(self) -> None:
        """Provision the interaction server session (no-op for some backends)."""
        ...

    def poll(self) -> list[Interaction]:
        """Return interactions received since the last poll."""
        ...


class NullOastBackend:
    """Used when no interaction server is configured: never yields interactions."""

    domain = "oast.local"

    def register(self) -> None:
        return None

    def poll(self) -> list[Interaction]:
        return []


@dataclass
class OastListener:
    backend: OastBackend
    # token -> node id (the request/parameter that carried this callback URL)
    _tokens: dict[str, str] = field(default_factory=dict)

    def available(self) -> bool:
        return not isinstance(self.backend, NullOastBackend)

    def new_callback(self, node_id: str) -> tuple[str, str]:
        """Mint a unique token + callback host to embed in a payload.

        Returns (token, callback_host). Inject the host into the payload
        (e.g. `http://<host>/`); a callback to it later correlates to node_id.
        """
        token = secrets.token_hex(10)
        self._tokens[token] = node_id
        return token, f"{token}.{self.backend.domain}"

    def _node_for(self, received_token: str) -> str | None:
        # A callback host is typically "<token>.<domain>"; match exact or prefix.
        if received_token in self._tokens:
            return self._tokens[received_token]
        for token, node in self._tokens.items():
            if received_token.startswith(token):
                return node
        return None

    def poll_and_correlate(self, *, discipline: str) -> list[Finding]:
        """Poll the backend and turn correlated interactions into findings."""
        findings: list[Finding] = []
        for it in self.backend.poll():
            node = self._node_for(it.token)
            if node is None:
                continue  # not one of ours (or already expired)
            findings.append(
                Finding(
                    discipline=discipline,
                    source="oast",
                    engine_layer=EngineLayer.DETERMINISTIC,
                    title=f"Out-of-band interaction ({it.protocol.upper()}) — blind vulnerability",
                    description=(
                        f"A {it.protocol.upper()} callback reached the OAST listener from a "
                        f"payload injected at {node}. This confirms out-of-band interaction "
                        "(e.g. blind SSRF/RCE/SQLi)."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    cwe="CWE-918" if it.protocol in {"http", "https", "dns"} else None,
                    rule_id=f"oast-{it.protocol}",
                    location=Location(route=node),
                    evidence=Evidence(
                        oast_token=it.token,
                        steps=[f"{it.protocol} callback from {it.remote_addr}".strip()],
                    ),
                )
            )
        return findings
