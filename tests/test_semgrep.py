import json
from pathlib import Path

from trinetra.engines.sast.semgrep import parse_semgrep_sarif
from trinetra.models.finding import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample.sarif"


def test_parse_semgrep_sarif_normalizes_findings():
    sarif = json.loads(FIXTURE.read_text())
    findings = parse_semgrep_sarif(sarif, discipline="web")
    assert len(findings) == 2

    by_rule = {f.rule_id: f for f in findings}
    subprocess = by_rule["python.lang.security.audit.dangerous-subprocess-use"]
    assert subprocess.cwe == "CWE-78"
    assert subprocess.severity == Severity.HIGH  # SARIF "error"
    assert subprocess.location.file == "app/exec.py"
    assert subprocess.location.line == 12
    assert subprocess.source == "semgrep"
    assert subprocess.discipline == "web"

    xss = by_rule["python.flask.security.injection.raw-html-format"]
    assert xss.cwe == "CWE-79"
    assert xss.severity == Severity.MEDIUM  # SARIF "warning"


def test_empty_sarif_yields_no_findings():
    assert parse_semgrep_sarif({"runs": []}) == []


def test_security_severity_property_overrides_coarse_level():
    # Registry rules carry a CVSS-style security-severity; a critical score must
    # win over Semgrep's coarse SARIF level ("warning").
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "r.sqli",
                                "properties": {
                                    "tags": ["CWE-89"],
                                    "security-severity": "9.8",
                                },
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "r.sqli",
                        "level": "warning",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db.py"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_semgrep_sarif(sarif)
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].cwe == "CWE-89"


def test_falls_back_to_rule_default_level_when_result_level_missing():
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "r.x", "defaultConfiguration": {"level": "error"}}
                        ]
                    }
                },
                "results": [{"ruleId": "r.x", "message": {"text": "x"}}],
            }
        ]
    }
    assert parse_semgrep_sarif(sarif)[0].severity == Severity.HIGH
