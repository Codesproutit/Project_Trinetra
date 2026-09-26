from trinetra.models.finding import Finding, Location, Severity


def _finding(**kw):
    base = dict(discipline="web", source="semgrep", title="SQL Injection", cwe="CWE-89")
    base.update(kw)
    return Finding(**base)


def test_fingerprint_is_stable_across_instances():
    a = _finding(location=Location(file="app/db.py", line=10))
    b = _finding(location=Location(file="app/db.py", line=10), description="different text")
    # Same identity (rule/cwe/location) -> same fingerprint, ignoring volatile fields.
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_by_location():
    a = _finding(location=Location(file="app/db.py", line=10))
    b = _finding(location=Location(file="app/db.py", line=99))
    assert a.fingerprint != b.fingerprint


def test_sarif_level_mapping():
    assert _finding(severity=Severity.CRITICAL).sarif_level == "error"
    assert _finding(severity=Severity.MEDIUM).sarif_level == "warning"
    assert _finding(severity=Severity.INFO).sarif_level == "note"
