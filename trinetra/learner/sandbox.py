"""The Docker fixture gate — the precision guarantee, stated honestly.

Before a candidate rule joins a brain it must prove itself on a versioned corpus:
fire on the vulnerable fixture AND stay silent on the remediated one. Only a rule
that does both is promoted. This is what makes the honest claim — "measured
precision on a versioned corpus" — real, and it is why we never say "zero false
positives."

Running a rule needs an engine (Semgrep) in an ephemeral container, so the runner
is pluggable behind `RuleRunner`. Crucially the gate is FAIL-CLOSED: if no runner
is available (no Docker / no Semgrep here), `validate()` returns `skipped` and the
learner promotes nothing. An unvalidated rule never enters a brain.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from trinetra.models.rule import Rule

logger = logging.getLogger(__name__)


@runtime_checkable
class RuleRunner(Protocol):
    def available(self) -> bool: ...
    def fires(self, rule: Rule, fixture_dir: str) -> bool:
        """True if the rule matches anything in the fixture directory."""
        ...


@dataclass
class GateResult:
    status: str  # "passed" | "rejected" | "skipped"
    tp: bool = False  # fired on the vulnerable fixture
    fp: bool = False  # fired on the remediated fixture

    @property
    def passed(self) -> bool:
        return self.status == "passed"


class SemgrepRuleRunner:
    """Runs a candidate rule with a local Semgrep. available() is False when the
    binary or PyYAML (to emit the rule) is missing — the gate then skips."""

    def __init__(self, binary: str = "semgrep"):
        self.binary = binary

    def available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        try:
            import yaml  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def fires(self, rule: Rule, fixture_dir: str) -> bool:  # pragma: no cover - needs semgrep
        import yaml

        with tempfile.TemporaryDirectory() as td:
            rule_file = Path(td) / "rule.yml"
            rule_file.write_text(yaml.safe_dump({"rules": [rule.to_semgrep()]}))
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self.binary, "--quiet", "--json", "--config", str(rule_file), fixture_dir],
                capture_output=True,
                text=True,
                check=False,
            )
            import json

            try:
                return bool(json.loads(proc.stdout).get("results"))
            except (json.JSONDecodeError, ValueError):
                return False


class SandboxValidator:
    """Gates a candidate rule against a positive/negative fixture pair."""

    def __init__(self, runner: RuleRunner, positive_dir: str, negative_dir: str):
        self.runner = runner
        self.positive_dir = positive_dir
        self.negative_dir = negative_dir

    def validate(self, rule: Rule) -> GateResult:
        if not self.runner.available():
            logger.info("No rule runner available; skipping validation (fail-closed).")
            return GateResult(status="skipped")
        tp = self.runner.fires(rule, self.positive_dir)
        fp = self.runner.fires(rule, self.negative_dir)
        return GateResult(status="passed" if (tp and not fp) else "rejected", tp=tp, fp=fp)
