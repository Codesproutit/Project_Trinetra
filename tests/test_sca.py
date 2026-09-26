from trinetra.engines.sca.sca_scanner import (
    Package,
    ScaScanner,
    discover_packages,
    osv_vulns_to_findings,
    parse_package_json,
    parse_requirements,
)
from trinetra.models.finding import Severity


def test_parse_requirements_pins_only():
    text = "flask==2.0.1\n# comment\nrequests>=2.0\n-r other.txt\ndjango==3.2.0\n"
    pkgs = parse_requirements(text)
    assert Package("flask", "2.0.1", "PyPI") in pkgs
    assert Package("django", "3.2.0", "PyPI") in pkgs
    # requests uses >= (a range) so it is not pinned/queried
    assert all(p.name != "requests" for p in pkgs)


def test_parse_package_json_strips_range_markers():
    text = '{"dependencies": {"lodash": "^4.17.20"}, "devDependencies": {"jest": "~29.0.0"}}'
    pkgs = parse_package_json(text)
    assert Package("lodash", "4.17.20", "npm") in pkgs
    assert Package("jest", "29.0.0", "npm") in pkgs


def test_discover_packages(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")
    sub = tmp_path / "frontend"
    sub.mkdir()
    (sub / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}')
    pkgs = discover_packages(tmp_path)
    names = {p.name for p in pkgs}
    assert names == {"flask", "lodash"}


def test_osv_vulns_to_findings_maps_severity_and_cwe():
    pkg = Package("flask", "0.12.0", "PyPI")
    vulns = [
        {
            "id": "GHSA-xxxx",
            "summary": "XSS in Flask",
            "aliases": ["CVE-2019-1010083"],
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
        }
    ]
    findings = osv_vulns_to_findings(pkg, vulns, discipline="web")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.cwe == "CWE-79"
    assert f.rule_id == "GHSA-xxxx"
    assert any("CVE-2019-1010083" in r for r in f.references)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload
        self.calls = []

    def post(self, url, *, json):
        self.calls.append((url, json))
        return _FakeResponse(self._payload)


def test_scanner_query_osv_with_injected_client():
    client = _FakeClient({"vulns": [{"id": "GHSA-1", "database_specific": {"severity": "LOW"}}]})
    scanner = ScaScanner(client=client)
    vulns = scanner.query_osv(Package("flask", "2.0.1", "PyPI"))
    assert vulns[0]["id"] == "GHSA-1"
    assert client.calls[0][1]["package"]["ecosystem"] == "PyPI"


def test_scanner_scan_end_to_end(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==0.12.0\n")
    client = _FakeClient(
        {
            "vulns": [
                {"id": "GHSA-2", "summary": "bug", "database_specific": {"severity": "CRITICAL"}}
            ]
        }
    )
    findings = ScaScanner(client=client).scan(str(tmp_path), discipline="api")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].discipline == "api"
