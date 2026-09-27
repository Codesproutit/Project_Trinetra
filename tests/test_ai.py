"""Tests for the AI cognitive layer: dedup gate, verdict parsing, reviewer."""

from trinetra.ai import AiReviewer, needs_review, parse_verdict
from trinetra.models.finding import (
    Confidence,
    EngineLayer,
    Finding,
    Location,
    Severity,
)
from trinetra.providers.base import Completion
from trinetra.providers.router import ProviderRouter


def _f(sev=Severity.HIGH, conf=Confidence.THEORETICAL, layer=EngineLayer.DETERMINISTIC, rule="r"):
    return Finding(
        discipline="web",
        source="semgrep",
        title="candidate",
        rule_id=rule,
        severity=sev,
        confidence=conf,
        engine_layer=layer,
        location=Location(file="a.py", line=1),
    )


def test_needs_review_selects_only_unsettled_deterministic_findings():
    findings = [
        _f(sev=Severity.HIGH),  # yes
        _f(sev=Severity.LOW, rule="low"),  # no: below min severity
        _f(conf=Confidence.CONFIRMED, rule="conf"),  # no: already confirmed
        _f(layer=EngineLayer.AI, rule="ai"),  # no: already an AI finding
    ]
    picked = needs_review(findings)
    assert len(picked) == 1
    assert picked[0].rule_id == "r"


def test_parse_verdict_tolerates_fences_and_prose():
    text = 'Here is my call:\n```json\n{"verdict":"false_positive","severity":"low"}\n```'
    v = parse_verdict(text)
    assert v.is_false_positive
    assert v.severity == "low"


def test_parse_verdict_unparseable_is_uncertain_not_dropped():
    v = parse_verdict("I cannot answer in JSON.")
    assert v.verdict == "uncertain"
    assert v.is_false_positive is False


class _FakeProvider:
    name = "fake"

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0

    def available(self):
        return True

    def complete(self, prompt, *, model, system=None):
        reply = self._replies[self.calls % len(self._replies)]
        self.calls += 1
        return Completion(text=reply, input_tokens=100, output_tokens=20, model=model)


def test_reviewer_drops_false_positive_and_enriches_true_positive():
    provider = _FakeProvider(
        [
            '{"verdict":"false_positive","rationale":"constant arg"}',
            '{"verdict":"true_positive","severity":"critical","remediation":"parameterize"}',
        ]
    )
    reviewer = AiReviewer(ProviderRouter(provider))
    outcome = reviewer.review([_f(rule="fp"), _f(rule="tp")])
    assert outcome.reviewed == 2
    assert outcome.dropped == 1
    assert len(outcome.findings) == 1
    kept = outcome.findings[0]
    assert kept.severity == Severity.CRITICAL
    assert kept.remediation == "parameterize"
    assert any("AI triage" in s for s in kept.evidence.steps)


def test_reviewer_available_reflects_provider():
    class _NoKey:
        name = "nokey"

        def available(self):
            return False

        def complete(self, prompt, *, model, system=None):  # pragma: no cover
            raise AssertionError("should not be called")

    assert AiReviewer(ProviderRouter(_NoKey())).available() is False
    assert AiReviewer(ProviderRouter(_FakeProvider(["{}"]))).available() is True
