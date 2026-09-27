from trinetra.models.finding import Finding, Location, Severity
from trinetra.reporting.sarif import findings_to_sarif


def test_sarif_structure_and_rules():
    findings = [
        Finding(
            discipline="web",
            source="semgrep",
            title="XSS",
            description="raw html",
            severity=Severity.HIGH,
            cwe="CWE-79",
            rule_id="rule.xss",
            location=Location(file="app/views.py", line=40),
        ),
        Finding(
            discipline="web",
            source="sca",
            title="Vuln dep",
            severity=Severity.CRITICAL,
            rule_id="GHSA-1",
            location=Location(file="PyPI:flask@0.12.0"),
        ),
    ]
    sarif = findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Trinetra"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2

    xss = next(r for r in run["results"] if r["ruleId"] == "rule.xss")
    assert xss["level"] == "error"
    assert xss["locations"][0]["physicalLocation"]["region"]["startLine"] == 40
    assert xss["properties"]["cwe"] == "CWE-79"


def test_shared_rule_deduplicated_in_driver():
    f = lambda: Finding(discipline="web", source="semgrep", title="X", rule_id="same")  # noqa: E731
    sarif = findings_to_sarif([f(), f()])
    # Two results but one rule definition.
    assert len(sarif["runs"][0]["results"]) == 2
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
