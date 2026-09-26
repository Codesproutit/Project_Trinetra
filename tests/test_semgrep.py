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
