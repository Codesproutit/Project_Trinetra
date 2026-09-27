"""The live activity model — what the tester watches during a scan.

Every request, payload and step the pipeline emits becomes an ActivityEvent, kept
category-wise so the dashboard can show progress per discipline/engine. This is
the pure data layer; the websocket server (server.py) streams it, and is optional.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field


@dataclass
class ActivityEvent:
    category: str  # e.g. "sast", "dast", "oast", "ai", "learner"
    action: str  # short verb, e.g. "request", "finding", "promote"
    detail: str = ""
    discipline: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ActivityLog:
    events: list[ActivityEvent] = field(default_factory=list)

    def append(
        self, category: str, action: str, detail: str = "", discipline: str = ""
    ) -> ActivityEvent:
        event = ActivityEvent(
            category=category, action=action, detail=detail, discipline=discipline
        )
        self.events.append(event)
        return event

    def by_category(self) -> dict[str, list[ActivityEvent]]:
        grouped: dict[str, list[ActivityEvent]] = {}
        for e in self.events:
            grouped.setdefault(e.category, []).append(e)
        return grouped

    def to_list(self) -> list[dict]:
        return [e.to_dict() for e in self.events]
