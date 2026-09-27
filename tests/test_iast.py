"""Tests for the IAST bridge: task derivation, OAST minting, and correlation."""

from trinetra.engines.oast import NullOastBackend, OastListener
from trinetra.iast import correlate, derive_tasks, mint_oast_callbacks, vuln_class
from trinetra.models.finding import Confidence, Finding, Location, Severity


def _static(cwe, *, source="semgrep", param=None, conf=Confidence.THEORETICAL):
    return Finding(
        discipline="web",
        source=source,
        title=f"sink {cwe}",
        rule_id=f"rule-{cwe}",
        severity=Severity.HIGH,
        confidence=conf,
        cwe=cwe,
        location=Location(file="app/db.py", line=12, param=param),
    )


def _dynamic(cwe, *, source="zap", param=None):
    return Finding(
        discipline="web",
        source=source,
        title=f"confirmed {cwe}",
        rule_id=f"dyn-{cwe}",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe=cwe,
        location=Location(route="http://tgt/item", param=param),
    )


def test_vuln_class_mapping():
    assert vuln_class("CWE-89") == "sql_injection"
    assert vuln_class("CWE-918") == "ssrf"
    assert vuln_class("cwe-79") == "xss"  # case-insensitive
    assert vuln_class("CWE-1234") is None
    assert vuln_class(None) is None


def test_derive_tasks_only_injectable_static_findings():
    findings = [
        _static("CWE-89"),  # SQLi -> task, blind
        _static("CWE-79"),  # XSS -> task, not blind
        _static("CWE-798"),  # hardcoded secret -> not bridgeable, skipped
        _dynamic("CWE-89"),  # already dynamic -> skipped
        _static("CWE-89", conf=Confidence.CONFIRMED),  # already confirmed -> skipped
    ]
    tasks = derive_tasks(findings)
    classes = {t.vuln_class for t in tasks}
    assert classes == {"sql_injection", "xss"}
    sqli = next(t for t in tasks if t.vuln_class == "sql_injection")
    xss = next(t for t in tasks if t.vuln_class == "xss")
    assert sqli.blind is True
    assert xss.blind is False
    assert sqli.file == "app/db.py" and sqli.line == 12


def test_mint_oast_callbacks_only_for_blind_tasks_when_available():
    tasks = derive_tasks([_static("CWE-918"), _static("CWE-79")])  # ssrf(blind), xss(not)
    listener = OastListener(backend=_FakeBackend())
    mint_oast_callbacks(tasks, listener)
    ssrf = next(t for t in tasks if t.vuln_class == "ssrf")
    xss = next(t for t in tasks if t.vuln_class == "xss")
    assert ssrf.oast_token is not None
    assert xss.oast_token is None


def test_mint_oast_callbacks_noop_without_backend():
    tasks = derive_tasks([_static("CWE-918")])
    mint_oast_callbacks(tasks, OastListener(backend=NullOastBackend()))
    assert tasks[0].oast_token is None


def test_correlate_upgrades_matched_static_finding():
    static = [_static("CWE-89")]
    dynamic = [_dynamic("CWE-89")]
    result = correlate(static, dynamic)
    assert result.confirmed_count == 1
    upgraded = result.findings[0]
    assert upgraded.confidence == Confidence.CONFIRMED
    assert any("IAST" in s for s in upgraded.evidence.steps)


def test_correlate_respects_param_disagreement():
    static = [_static("CWE-89", param="id")]
    dynamic = [_dynamic("CWE-89", param="search")]
    result = correlate(static, dynamic)
    assert result.confirmed_count == 0
    assert result.findings[0].confidence == Confidence.THEORETICAL


def test_correlate_ignores_unrelated_classes():
    static = [_static("CWE-89")]
    dynamic = [_dynamic("CWE-79")]  # different class
    result = correlate(static, dynamic)
    assert result.confirmed_count == 0


def test_correlate_carries_oast_token_from_dynamic():
    static = [_static("CWE-918")]
    dyn = _dynamic("CWE-918")
    dyn.evidence.oast_token = "abc123"
    result = correlate(static, [dyn])
    assert result.findings[0].evidence.oast_token == "abc123"


class _FakeBackend:
    domain = "oast.test"

    def register(self):
        return None

    def poll(self):
        return []
