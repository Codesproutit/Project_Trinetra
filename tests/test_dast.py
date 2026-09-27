"""Tests for the DAST adapters' pure normalizers (no live ZAP / nuclei needed)."""

from trinetra.engines.dast.nuclei import NucleiAdapter, parse_nuclei_jsonl
from trinetra.engines.dast.zap import ZapAdapter, parse_zap_alerts
from trinetra.models.finding import Confidence, Severity


def test_parse_zap_alerts_maps_risk_cwe_and_location():
    alerts = [
        {
            "alert": "SQL Injection",
            "risk": "High",
            "cweid": "89",
            "url": "http://tgt/login",
            "param": "username",
            "description": "SQLi in login",
            "solution": "Use parameterized queries",
            "reference": "https://owasp.org/sqli",
            "pluginId": "40018",
            "message": "POST /login",
            "evidence": "syntax error",
        }
    ]
    findings = parse_zap_alerts(alerts, discipline="web")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED  # ZAP hit a live target
    assert f.cwe == "CWE-89"
    assert f.location.route == "http://tgt/login"
    assert f.location.param == "username"
    assert f.source == "zap"
    assert f.remediation == "Use parameterized queries"


def test_parse_zap_alerts_drops_placeholder_cwe():
    findings = parse_zap_alerts(
        [{"alert": "Info leak", "risk": "Low", "cweid": "-1", "url": "http://tgt/"}],
        discipline="web",
    )
    assert findings[0].cwe is None
    assert findings[0].severity == Severity.LOW


def test_parse_zap_alerts_empty():
    assert parse_zap_alerts([], discipline="web") == []


def test_parse_nuclei_jsonl_maps_fields():
    line = (
        '{"template-id":"CVE-2021-1234","matched-at":"http://tgt/x",'
        '"info":{"name":"Some CVE","severity":"critical",'
        '"classification":{"cwe-id":["CWE-79"]},"reference":["https://x"]}}'
    )
    findings = parse_nuclei_jsonl(line, discipline="api")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.cwe == "CWE-79"
    assert f.title == "Some CVE"
    assert f.location.route == "http://tgt/x"
    assert f.source == "nuclei"
    assert f.confidence == Confidence.CONFIRMED


def test_parse_nuclei_jsonl_skips_blank_and_bad_lines():
    text = "\n".join(["", "   ", "not json", '{"template-id":"t","info":{"severity":"low"}}'])
    findings = parse_nuclei_jsonl(text, discipline="web")
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_nuclei_cwe_normalizes_bare_number():
    line = '{"template-id":"t","info":{"severity":"medium","classification":{"cwe-id":["918"]}}}'
    findings = parse_nuclei_jsonl(line, discipline="web")
    assert findings[0].cwe == "CWE-918"


def test_adapters_are_target_kind_and_unavailable_offline():
    # No ZAP daemon and no nuclei binary in the test env => degrade, don't crash.
    zap = ZapAdapter(address="http://127.0.0.1:1", client=None)
    nuclei = NucleiAdapter(binary="nuclei-does-not-exist")
    assert zap.input_kind == "target"
    assert nuclei.input_kind == "target"
    assert zap.available() is False
    assert nuclei.available() is False
