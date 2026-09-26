import json
from datetime import date

import pytest

from trinetra.models.scope import OutOfScopeError, Scope, ScopeManifest, ScopeRules, Target
from trinetra.orchestrator.scope_guard import RateLimiter, ScopeGuard


def _manifest(**kw):
    base = dict(
        engagement="test",
        authorized_by="tester",
        in_scope=ScopeRules(hosts=["app.acme.test"], url_globs=["https://app.acme.test/*"]),
        out_of_scope=["https://app.acme.test/admin/*"],
    )
    base.update(kw)
    return ScopeManifest(**base)


def test_in_scope_host_and_url():
    guard = ScopeGuard(Scope(_manifest()))
    guard.assert_in_scope(Target(host="app.acme.test"))
    guard.assert_in_scope(Target(url="https://app.acme.test/login"))


def test_out_of_scope_rejected():
    guard = ScopeGuard(Scope(_manifest()))
    with pytest.raises(OutOfScopeError):
        guard.assert_in_scope(Target(url="https://evil.example.com/"))


def test_out_of_scope_overrides_in_scope():
    guard = ScopeGuard(Scope(_manifest()))
    with pytest.raises(OutOfScopeError):
        guard.assert_in_scope(Target(url="https://app.acme.test/admin/panel"))


def test_expired_scope_refused_on_load(tmp_path):
    manifest = _manifest(valid_until=date(2000, 1, 1))
    p = tmp_path / "scope.json"
    p.write_text(manifest.model_dump_json())
    with pytest.raises(OutOfScopeError):
        ScopeGuard.load(p)


def test_rate_limiter_waits():
    calls = {"slept": 0.0}
    clock = {"t": 0.0}

    def fake_sleep(s):
        calls["slept"] += s
        clock["t"] += s

    def fake_now():
        return clock["t"]

    limiter = RateLimiter(rps=10)  # 0.1s min interval
    limiter.acquire("h", sleep=fake_sleep, now=fake_now)  # first: no wait
    limiter.acquire("h", sleep=fake_sleep, now=fake_now)  # second: must wait ~0.1s
    assert calls["slept"] == pytest.approx(0.1, abs=1e-6)


def test_load_json_manifest(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(_manifest().model_dump(mode="json")))
    guard = ScopeGuard.load(p)
    guard.assert_in_scope(Target(host="app.acme.test"))
