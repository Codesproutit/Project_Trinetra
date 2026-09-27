"""The self-evolving loop: novel confirmed finding → rule → gate → brain.

Only findings that are both CONFIRMED (dynamic reach proved the theory) and novel
(the brain doesn't already know them) are considered. Each becomes a candidate
rule, runs the sandbox gate, and is promoted to the discipline's brain only on a
pass. Rejections and gate-skips promote nothing — the loop is conservative by
design, because a bad promoted rule poisons every future scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from trinetra.brains.base import Brain
from trinetra.learner.sandbox import SandboxValidator
from trinetra.learner.synthesize import synthesize
from trinetra.models.finding import Confidence, Finding
from trinetra.models.rule import Rule

logger = logging.getLogger(__name__)


@dataclass
class LearnOutcome:
    promoted: list[Rule] = field(default_factory=list)
    rejected: int = 0  # failed the fixture gate
    skipped: int = 0  # already known, or gate unavailable
    considered: int = 0


class Learner:
    def __init__(self, brains: dict[str, Brain], validator: SandboxValidator):
        self.brains = brains
        self.validator = validator

    def observe(self, findings: list[Finding]) -> LearnOutcome:
        out = LearnOutcome()
        for f in findings:
            if f.confidence != Confidence.CONFIRMED:
                continue
            brain = self.brains.get(f.discipline)
            if brain is None:
                continue
            out.considered += 1
            if brain.knows(f):
                out.skipped += 1
                continue
            rule = synthesize(f)
            result = self.validator.validate(rule)
            if result.status == "skipped":
                out.skipped += 1
                continue
            if result.passed:
                brain.promote(rule)
                out.promoted.append(rule)
            else:
                out.rejected += 1
        return out
