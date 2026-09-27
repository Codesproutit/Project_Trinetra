"""Scope & authorization gate — enforced in code, not by operator discipline.

Nothing reaches an engine without passing through ScopeGuard. The rate limiter
caps per-host request volume so a scan can never overwhelm a target.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from trinetra.models.scope import OutOfScopeError, Scope, ScopeManifest, Target


def _load_manifest_dict(path: Path) -> dict:
    text = path.read_text()
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml  # optional dependency
        except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
            raise RuntimeError(
                "PyYAML is required to load a YAML scope manifest; "
                "install it or provide the manifest as JSON."
            ) from exc
        return yaml.safe_load(text)
    return json.loads(text)


class RateLimiter:
    """Simple per-host token-bucket-ish limiter.

    Deliberately small and synchronous for the MVP; the DAST phase swaps in an
    async limiter shared across the crawler's worker pool.
    """

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last: dict[str, float] = {}

    def acquire(self, host: str, *, sleep=time.sleep, now=time.monotonic) -> None:
        if self.min_interval <= 0:
            return
        last = self._last.get(host)
        current = now()
        if last is not None:
            wait = self.min_interval - (current - last)
            if wait > 0:
                sleep(wait)
                current = now()
        self._last[host] = current


class ScopeGuard:
    """Loads a signed scope manifest and validates every target against it."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self.limiter = RateLimiter(scope.manifest.rate_limit_rps)

    @classmethod
    def load(cls, manifest_path: str | Path) -> ScopeGuard:
        path = Path(manifest_path)
        manifest = ScopeManifest.model_validate(_load_manifest_dict(path))
        scope = Scope(manifest)
        if scope.expired():
            raise OutOfScopeError(
                f"Scope manifest '{manifest.engagement}' expired on {manifest.valid_until}."
            )
        return cls(scope)

    def assert_in_scope(self, target: Target) -> None:
        if not self.scope.contains(target):
            raise OutOfScopeError(f"Target {target.model_dump(exclude_none=True)} is out of scope.")
