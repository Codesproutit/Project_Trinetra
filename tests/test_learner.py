"""Tests for the self-evolving learner: synthesize, brain, sandbox gate, loop."""

from trinetra.brains import FileBrain
from trinetra.learner import Learner, SandboxValidator, synthesize
from trinetra.models.finding import Confidence, Finding, Location, Severity


def _finding(cwe="CWE-89", conf=Confidence.CONFIRMED, disc="web", rule="sqli"):
    return Finding(
        discipline=disc,
        source="zap",
        title="SQL injection",
        rule_id=rule,
        severity=Severity.HIGH,
        confidence=conf,
        cwe=cwe,
        location=Location(route="http://t/x"),
    )


class _Runner:
    def __init__(self, avail=True, pos=True, neg=False):
        self._avail, self._pos, self._neg = avail, pos, neg

    def available(self):
        return self._avail

    def fires(self, rule, fixture_dir):
        return self._pos if fixture_dir == "pos" else self._neg


def _validator(**kw):
    return SandboxValidator(_Runner(**kw), positive_dir="pos", negative_dir="neg")


# --- synthesize ---------------------------------------------------------------

def test_synthesize_builds_discipline_scoped_rule():
    rule = synthesize(_finding())
    assert rule.discipline == "web"
    assert rule.id.startswith("trinetra.web.learned.")
    assert rule.cwe == "CWE-89"
    assert rule.metadata["origin_fingerprint"] == _finding().fingerprint


# --- FileBrain ----------------------------------------------------------------

def test_filebrain_promote_knows_and_load(tmp_path):
    brain = FileBrain("web", tmp_path)
    f = _finding()
    assert brain.knows(f) is False
    brain.promote(synthesize(f))
    assert brain.knows(f) is True  # signature recorded
    rules = brain.load_rules()
    assert len(rules) == 1 and rules[0].discipline == "web"


# --- sandbox gate -------------------------------------------------------------

def test_gate_passes_when_fires_on_vuln_and_silent_on_safe():
    result = _validator(pos=True, neg=False).validate(synthesize(_finding()))
    assert result.passed and result.status == "passed"


def test_gate_rejects_when_it_also_fires_on_safe_fixture():
    result = _validator(pos=True, neg=True).validate(synthesize(_finding()))
    assert result.status == "rejected" and not result.passed


def test_gate_skips_fail_closed_when_runner_unavailable():
    result = _validator(avail=False).validate(synthesize(_finding()))
    assert result.status == "skipped" and not result.passed


# --- learner loop -------------------------------------------------------------

def test_learner_promotes_novel_confirmed_finding(tmp_path):
    brain = FileBrain("web", tmp_path)
    learner = Learner({"web": brain}, _validator(pos=True, neg=False))
    out = learner.observe([_finding()])
    assert len(out.promoted) == 1
    assert brain.knows(_finding()) is True


def test_learner_ignores_theoretical_and_known(tmp_path):
    brain = FileBrain("web", tmp_path)
    learner = Learner({"web": brain}, _validator(pos=True, neg=False))
    # theoretical -> not considered at all
    out = learner.observe([_finding(conf=Confidence.THEORETICAL)])
    assert out.considered == 0 and out.promoted == []
    # promote once, then a second identical confirmed finding is skipped as known
    learner.observe([_finding()])
    out2 = learner.observe([_finding()])
    assert out2.skipped == 1 and out2.promoted == []


def test_learner_rejects_rule_that_fails_gate(tmp_path):
    brain = FileBrain("web", tmp_path)
    learner = Learner({"web": brain}, _validator(pos=True, neg=True))
    out = learner.observe([_finding()])
    assert out.rejected == 1 and out.promoted == []
    assert brain.knows(_finding()) is False  # not learned


def test_learner_skip_when_gate_unavailable_promotes_nothing(tmp_path):
    brain = FileBrain("web", tmp_path)
    learner = Learner({"web": brain}, _validator(avail=False))
    out = learner.observe([_finding()])
    assert out.promoted == [] and out.skipped == 1
