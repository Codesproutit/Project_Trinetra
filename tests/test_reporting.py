"""Tests for Phase 7: evidence chain-of-custody, report rendering, dashboard model."""

import pytest

from trinetra.dashboard import ActivityLog, Step, fork
from trinetra.models.finding import Confidence, Evidence, Finding, Location, Severity
from trinetra.reporting.evidence import attach_evidence, evidence_for
from trinetra.reporting.render import render_report, write_reports


def _f(title="SQLi", sev=Severity.HIGH, cwe="CWE-89"):
    return Finding(
        discipline="web",
        source="zap",
        title=title,
        rule_id="sqli",
        severity=sev,
        confidence=Confidence.CONFIRMED,
        cwe=cwe,
        location=Location(route="http://t/x", param="id"),
        evidence=Evidence(request="GET /x?id=1", response="500", steps=["injected 1' OR '1'='1"]),
        remediation="Use parameterized queries.",
    )


# --- evidence -----------------------------------------------------------------

def test_evidence_hash_is_stable_and_tamper_evident():
    f = _f()
    a = evidence_for(f)
    b = evidence_for(f)
    assert a.sha256 == b.sha256  # deterministic
    f2 = f.model_copy(deep=True)
    f2.evidence.response = "200"  # change evidence
    assert evidence_for(f2).sha256 != a.sha256  # hash changes


def test_attach_evidence_keyed_by_fingerprint():
    f = _f()
    ev = attach_evidence([f])
    assert set(ev) == {f.fingerprint}
    assert ev[f.fingerprint].request == "GET /x?id=1"


# --- rendering ----------------------------------------------------------------

def test_exec_report_has_summary_and_highlights():
    text = render_report([_f(), _f(title="XSS", sev=Severity.LOW, cwe="CWE-79")], fmt="exec")
    assert "Executive Summary" in text
    assert "Severity summary" in text
    assert "SQLi" in text  # high finding is a highlight
    assert "| high | 1 |" in text


@pytest.mark.parametrize("fmt,label", [("cert-in", "CERT-In"), ("crest", "CREST")])
def test_formal_reports_include_findings_and_evidence_hash(fmt, label):
    f = _f()
    text = render_report([f], fmt=fmt)
    assert label in text
    assert "Evidence SHA-256" in text
    assert evidence_for(f).sha256 in text
    assert "Use parameterized queries." in text


def test_render_report_rejects_unknown_format():
    with pytest.raises(ValueError):
        render_report([_f()], fmt="pdf")


def test_write_reports_creates_files(tmp_path):
    paths = write_reports([_f()], tmp_path / "out", ["exec", "cert-in"])
    names = sorted(p.name for p in paths)
    assert names == ["report-cert-in.md", "report-exec.md"]
    assert all(p.exists() and p.read_text() for p in paths)


# --- dashboard model ----------------------------------------------------------

def test_activity_log_records_and_groups():
    log = ActivityLog()
    log.append("dast", "request", "GET /x", discipline="web")
    log.append("oast", "callback", "http hit", discipline="web")
    log.append("dast", "finding", "SQLi", discipline="web")
    grouped = log.by_category()
    assert len(grouped["dast"]) == 2 and len(grouped["oast"]) == 1
    assert log.to_list()[0]["action"] == "request"


def test_replay_fork_overrides_without_mutating_original():
    step = Step(method="GET", url="http://t/x", headers={"A": "1"}, body="orig")
    forked = fork(step, body="tweaked", headers={"B": "2"})
    assert forked.body == "tweaked"
    assert forked.headers == {"A": "1", "B": "2"}
    assert step.body == "orig" and step.headers == {"A": "1"}  # original untouched
