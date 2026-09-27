"""OWASP ZAP adapter.

Drives ZAP's REST API (spider → active scan → alerts) against a running ZAP
daemon, then normalizes alerts to Finding. ZAP ships as a pinned container; the
adapter degrades gracefully (available() -> False) when no daemon is reachable,
so a scan reports "skipped" rather than crashing.

The alert normalizer is a pure function so it is tested without a live ZAP.
"""

from __future__ import annotations

import logging
import os
import time

import httpx

from trinetra.models.finding import (
    Confidence,
    EngineLayer,
    Evidence,
    Finding,
    Location,
    Severity,
)

logger = logging.getLogger(__name__)

# ZAP risk string -> our severity.
_RISK_TO_SEVERITY = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


def parse_zap_alerts(alerts: list[dict], *, discipline: str) -> list[Finding]:
    """Convert ZAP `core/view/alerts` entries into normalized Findings."""
    findings: list[Finding] = []
    for a in alerts:
        cwe_id = str(a.get("cweid", "")).strip()
        cwe = f"CWE-{cwe_id}" if cwe_id and cwe_id not in {"-1", "0"} else None
        evidence = Evidence(
            request=a.get("message") or None,
            response=a.get("evidence") or None,
        )
        findings.append(
            Finding(
                discipline=discipline,
                source="zap",
                engine_layer=EngineLayer.DETERMINISTIC,
                title=a.get("alert") or a.get("name") or "ZAP alert",
                description=a.get("description", ""),
                severity=_RISK_TO_SEVERITY.get(a.get("risk", "Low"), Severity.LOW),
                # ZAP issued the request against a live target, so a real alert
                # is a confirmed dynamic hit, not a theoretical one.
                confidence=Confidence.CONFIRMED,
                cwe=cwe,
                rule_id=str(a.get("pluginId") or a.get("alertRef") or a.get("alert", "")),
                location=Location(route=a.get("url"), param=a.get("param") or None),
                evidence=evidence,
                remediation=a.get("solution", ""),
                references=[r for r in [a.get("reference")] if r],
            )
        )
    return findings


class ZapAdapter:
    name = "zap"
    disciplines = ["web", "api"]
    input_kind = "target"

    def __init__(self, address: str | None = None, api_key: str | None = None, client=None):
        self.address = address or os.getenv("TRINETRA_ZAP_ADDR", "http://127.0.0.1:8080")
        self.api_key = api_key or os.getenv("TRINETRA_ZAP_APIKEY", "")
        self._client = client

    def _http(self) -> httpx.Client:
        return self._client or httpx.Client(base_url=self.address, timeout=30)

    def available(self) -> bool:
        """Reachable only if a ZAP daemon answers its version endpoint."""
        try:
            client = self._http()
            try:
                resp = client.get("/JSON/core/view/version/", params={"apikey": self.api_key})
                return resp.status_code == 200
            finally:
                if self._client is None:
                    client.close()
        except httpx.HTTPError:
            return False

    def scan(self, target: str, *, discipline: str = "web") -> list[Finding]:
        client = self._http()
        try:
            self._spider(client, target)
            self._active_scan(client, target)
            resp = client.get(
                "/JSON/core/view/alerts/", params={"baseurl": target, "apikey": self.api_key}
            )
            resp.raise_for_status()
            return parse_zap_alerts(resp.json().get("alerts", []), discipline=discipline)
        finally:
            if self._client is None:
                client.close()

    def _spider(self, client: httpx.Client, target: str) -> None:
        r = client.get("/JSON/spider/action/scan/", params={"url": target, "apikey": self.api_key})
        r.raise_for_status()
        scan_id = r.json().get("scan")
        self._await_status(client, "/JSON/spider/view/status/", scan_id)

    def _active_scan(self, client: httpx.Client, target: str) -> None:
        r = client.get("/JSON/ascan/action/scan/", params={"url": target, "apikey": self.api_key})
        r.raise_for_status()
        scan_id = r.json().get("scan")
        self._await_status(client, "/JSON/ascan/view/status/", scan_id)

    def _await_status(self, client: httpx.Client, view: str, scan_id, *, sleep=time.sleep) -> None:
        for _ in range(600):  # generous ceiling; each poll is ~1s
            r = client.get(view, params={"scanId": scan_id, "apikey": self.api_key})
            r.raise_for_status()
            if int(r.json().get("status", 0)) >= 100:
                return
            sleep(1)
