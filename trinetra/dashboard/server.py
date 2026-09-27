"""Optional live dashboard server (FastAPI + websocket).

FastAPI is an optional dependency and the browser UI needs a running process, so
this module imports FastAPI lazily and exposes `available()`. The activity model
(activity.py) and replay logic (replay.py) are the tested core; this is the thin
transport that streams them to a browser when the extra is installed.
"""

from __future__ import annotations

from trinetra.dashboard.activity import ActivityLog


def available() -> bool:
    try:
        import fastapi  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def create_app(log: ActivityLog):  # pragma: no cover - needs fastapi installed
    """Build a FastAPI app that serves the activity log. Requires trinetra[dashboard]."""
    if not available():
        raise RuntimeError(
            "FastAPI is not installed. Install with `pip install trinetra[dashboard]` "
            "to run the live dashboard."
        )
    from fastapi import FastAPI

    app = FastAPI(title="Trinetra activity")

    @app.get("/api/activity")
    def activity() -> list[dict]:
        return log.to_list()

    return app
