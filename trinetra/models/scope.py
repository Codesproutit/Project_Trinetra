"""Scope & authorization model.

This is a safety-critical schema: it encodes what an operator is authorized to
touch. The ScopeGuard (orchestrator/scope_guard.py) enforces it in code so a scan
can never be pointed at something outside the signed engagement.
"""

from __future__ import annotations

import fnmatch
from datetime import date

from pydantic import BaseModel, Field


class OutOfScopeError(Exception):
    """Raised when a target is not covered by the loaded scope manifest."""


class Target(BaseModel):
    """A single thing a scan may act on."""

    host: str | None = None
    url: str | None = None
    path: str | None = None  # local source path (white-box)


class ScopeRules(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    url_globs: list[str] = Field(default_factory=list)


class ScopeManifest(BaseModel):
    """The raw, signed engagement document, loaded from YAML/JSON."""

    engagement: str
    authorized_by: str
    valid_until: date | None = None
    in_scope: ScopeRules = Field(default_factory=ScopeRules)
    out_of_scope: list[str] = Field(default_factory=list)
    rate_limit_rps: float = 10.0


class Scope:
    """Runtime scope check built from a manifest.

    `contains` is deny-by-default: a target must match an in-scope rule AND not
    match any out-of-scope rule.
    """

    def __init__(self, manifest: ScopeManifest):
        self.manifest = manifest

    def expired(self, today: date | None = None) -> bool:
        if self.manifest.valid_until is None:
            return False
        return (today or date.today()) > self.manifest.valid_until

    def contains(self, target: Target) -> bool:
        candidates = [c for c in (target.host, target.url, target.path) if c]
        if not candidates:
            return False
        for value in candidates:
            if any(fnmatch.fnmatch(value, glob) for glob in self.manifest.out_of_scope):
                return False
        rules = self.manifest.in_scope
        for value in candidates:
            if value in rules.hosts:
                return True
            if any(fnmatch.fnmatch(value, glob) for glob in rules.url_globs):
                return True
        return False
