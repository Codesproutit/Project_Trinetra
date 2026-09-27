"""Per-discipline brains — one rule store per discipline, no sharing.

A pattern learned tearing down an APK never leaks into web rules: the learner
writes only to the brain of the discipline that produced the finding. Each brain
is a versioned directory of rules plus tracked precision. `knows()` is the strict-
dedup memory — a finding whose signature a brain already owns is never re-learned.

Storage is JSON (dependency-free); rules export to Semgrep when an engine runs
them. `promote()` is the ONLY way a rule enters a brain, and the learner calls it
solely after the sandbox gate passes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from trinetra.models.finding import Finding
from trinetra.models.rule import Rule


@runtime_checkable
class Brain(Protocol):
    discipline: str

    def load_rules(self) -> list[Rule]: ...
    def knows(self, finding: Finding) -> bool: ...
    def promote(self, rule: Rule) -> None: ...
    def precision(self) -> dict: ...


class FileBrain:
    """A filesystem-backed brain: rules/<id>.json + a state file of learned signatures."""

    def __init__(self, discipline: str, root: str | Path):
        self.discipline = discipline
        self.dir = Path(root) / discipline
        self.rules_dir = self.dir / "rules"
        self.state_file = self.dir / "promoted.json"
        self.precision_file = self.dir / "precision.json"

    def _promoted_signatures(self) -> set[str]:
        if not self.state_file.exists():
            return set()
        try:
            return set(json.loads(self.state_file.read_text()).get("signatures", []))
        except (json.JSONDecodeError, OSError):
            return set()

    def load_rules(self) -> list[Rule]:
        if not self.rules_dir.exists():
            return []
        rules: list[Rule] = []
        for path in sorted(self.rules_dir.glob("*.json")):
            try:
                rules.append(Rule.model_validate_json(path.read_text()))
            except (OSError, ValueError):
                continue
        return rules

    def knows(self, finding: Finding) -> bool:
        return finding.fingerprint in self._promoted_signatures()

    def promote(self, rule: Rule) -> None:
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        safe = rule.id.replace("/", "_").replace(":", "_")
        (self.rules_dir / f"{safe}.json").write_text(rule.model_dump_json(indent=2))
        sigs = self._promoted_signatures()
        origin = rule.metadata.get("origin_fingerprint")
        if origin:
            sigs.add(origin)
        self.state_file.write_text(json.dumps({"signatures": sorted(sigs)}, indent=2))

    def precision(self) -> dict:
        if self.precision_file.exists():
            try:
                return json.loads(self.precision_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"discipline": self.discipline, "rules": len(self.load_rules())}
