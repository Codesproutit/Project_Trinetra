"""Software Composition Analysis."""

from trinetra.engines.sca.sca_scanner import (
    Package,
    ScaScanner,
    discover_packages,
    osv_vulns_to_findings,
    parse_package_json,
    parse_requirements,
)

__all__ = [
    "ScaScanner",
    "Package",
    "discover_packages",
    "osv_vulns_to_findings",
    "parse_package_json",
    "parse_requirements",
]
