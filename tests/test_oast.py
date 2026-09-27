"""Tests for the OAST listener's token minting and callback correlation."""

from trinetra.engines.oast import Interaction, NullOastBackend, OastListener
from trinetra.models.finding import Confidence, Severity


class _FakeBackend:
    """Records queued interactions and hands them back on poll()."""

    domain = "oast.test"

    def __init__(self, interactions=None):
        self._queued = list(interactions or [])

    def register(self):
        return None

    def poll(self):
        out, self._queued = self._queued, []
        return out


def test_null_backend_is_unavailable_and_silent():
    listener = OastListener(backend=NullOastBackend())
    assert listener.available() is False
    assert listener.poll_and_correlate(discipline="web") == []


def test_new_callback_mints_unique_host_on_backend_domain():
    listener = OastListener(backend=_FakeBackend())
    token, host = listener.new_callback("param:redirect_uri")
    assert host == f"{token}.oast.test"
    token2, _ = listener.new_callback("param:redirect_uri")
    assert token != token2  # each injection point gets its own token


def test_correlated_interaction_becomes_confirmed_finding():
    backend = _FakeBackend()
    listener = OastListener(backend=backend)
    token, host = listener.new_callback("GET /fetch?url=")
    # A callback arrives to "<token>.<domain>" — the payload fired.
    backend._queued = [Interaction(token=host, protocol="http", remote_addr="10.0.0.9")]
    findings = listener.poll_and_correlate(discipline="api")
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == Confidence.CONFIRMED
    assert f.severity == Severity.HIGH
    assert f.cwe == "CWE-918"
    assert f.location.route == "GET /fetch?url="
    assert f.evidence.oast_token == host


def test_uncorrelated_interaction_is_ignored():
    backend = _FakeBackend([Interaction(token="somebody-elses-token", protocol="dns")])
    listener = OastListener(backend=backend)
    listener.new_callback("node-1")
    assert listener.poll_and_correlate(discipline="web") == []
