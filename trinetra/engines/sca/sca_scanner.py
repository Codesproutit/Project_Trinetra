"""SCA scanner (MVP).

Parses dependency manifests and queries the OSV.dev database (OSV aggregates NVD +
GitHub Advisory + ecosystem sources) for known vulnerabilities. This is a
dependency-light MVP that needs no Docker; the Trivy/Grype/Syft adapters — which
add full SBOM output and more ecosystems — plug in behind the same EngineAdapter
interface in a later phase.

The HTTP client is injected so the parsing and normalization logic is fully
unit-testable without network access.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

from trinetra.models.finding import EngineLayer, Finding, Location, Severity

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

_GHSA_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem string, e.g. "PyPI" or "npm"


class PostClient(Protocol):
    def post(self, url: str, *, json: dict): ...  # returns a response with .json()


def parse_requirements(text: str) -> list[Package]:
    """Parse a pip requirements.txt. Only pinned `name==version` lines are queried."""
    packages: list[Package] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)", line)
        if m:
            packages.append(Package(m.group(1), m.group(2), "PyPI"))
    return packages


def parse_package_json(text: str) -> list[Package]:
    """Parse a package.json's dependencies + devDependencies."""
    data = json.loads(text)
    packages: list[Package] = []
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            version = str(spec).lstrip("^~>=< ").strip()
            if re.match(r"^\d", version):  # skip ranges/tags we can't pin
                packages.append(Package(name, version, "npm"))
    return packages


def discover_packages(root: str | Path) -> list[Package]:
    """Find and parse supported manifests under a project root."""
    root = Path(root)
    packages: list[Package] = []
    for req in root.rglob("requirements.txt"):
        packages.extend(parse_requirements(req.read_text()))
    for pkg in root.rglob("package.json"):
        if "node_modules" in pkg.parts:
            continue
        packages.extend(parse_package_json(pkg.read_text()))
    return packages


def _severity_of(vuln: dict) -> Severity:
    label = (vuln.get("database_specific", {}) or {}).get("severity")
    if isinstance(label, str):
        return _GHSA_SEVERITY.get(label.upper(), Severity.MEDIUM)
    return Severity.MEDIUM


def _cwe_of(vuln: dict) -> str | None:
    cwes = (vuln.get("database_specific", {}) or {}).get("cwe_ids") or []
    return cwes[0] if cwes else None


def osv_vulns_to_findings(pkg: Package, vulns: list[dict], *, discipline: str) -> list[Finding]:
    findings: list[Finding] = []
    for vuln in vulns:
        vid = vuln.get("id", "UNKNOWN")
        aliases = vuln.get("aliases", [])
        title = f"{pkg.name} {pkg.version}: {vid}"
        findings.append(
            Finding(
                discipline=discipline,
                source="sca",
                engine_layer=EngineLayer.DETERMINISTIC,
                title=title[:200],
                description=vuln.get("summary") or vuln.get("details", "")[:500],
                severity=_severity_of(vuln),
                cwe=_cwe_of(vuln),
                rule_id=vid,
                location=Location(file=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"),
                remediation=f"Upgrade {pkg.name} past the affected range.",
                references=[f"https://osv.dev/vulnerability/{vid}"]
                + [f"https://nvd.nist.gov/vuln/detail/{a}" for a in aliases if a.startswith("CVE")],
            )
        )
    return findings


class ScaScanner:
    name = "sca"
    disciplines = ["web", "api"]

    def __init__(self, client: PostClient | None = None):
        self._client = client

    def available(self) -> bool:
        return True  # pure Python + HTTP; no external binary required

    def query_osv(self, pkg: Package) -> list[dict]:
        payload = {
            "version": pkg.version,
            "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
        }
        client = self._client or httpx.Client(timeout=20)
        try:
            resp = client.post(OSV_QUERY_URL, json=payload)
            resp.raise_for_status()
            return resp.json().get("vulns", []) or []
        finally:
            if self._client is None:
                client.close()

    def scan(self, target: str, *, discipline: str = "web") -> list[Finding]:
        findings: list[Finding] = []
        for pkg in discover_packages(target):
            try:
                vulns = self.query_osv(pkg)
            except httpx.HTTPError as exc:
                # A single lookup failing (offline, rate limit) must not kill the run;
                # skip this package and continue with the rest.
                logger.warning("OSV lookup failed for %s@%s: %s", pkg.name, pkg.version, exc)
                continue
            findings.extend(osv_vulns_to_findings(pkg, vulns, discipline=discipline))
        return findings
