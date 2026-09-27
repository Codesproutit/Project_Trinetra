"""Local control-panel server (optional FastAPI).

`trinetra serve` starts this on localhost. It is a thin transport over the tested
core: `environment.py` says what can run, `jobs.py` runs scans on background
threads, and this module just exposes them plus the static page. FastAPI and
uvicorn are optional (`pip install trinetra[dashboard]`), imported lazily so the
rest of Trinetra runs without them.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from trinetra.dashboard.environment import mode_readiness, probe_environment
from trinetra.dashboard.jobs import JobManager, ScanRequest

STATIC_DIR = Path(__file__).parent / "static"


def available() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def _require() -> None:
    if not available():
        raise RuntimeError(
            "FastAPI/uvicorn are not installed. Install with `pip install trinetra[dashboard]` "
            "to run the local control panel."
        )


def create_app(job_manager: JobManager | None = None):
    """Build the FastAPI app. A JobManager can be injected for tests."""
    _require()
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles

    jobs = job_manager or JobManager()
    app = FastAPI(title="Trinetra control panel", docs_url="/api/docs")

    @app.get("/api/environment")
    def environment() -> JSONResponse:
        env = probe_environment()
        return JSONResponse(
            {
                "capabilities": [asdict(c) for c in env.values()],
                "modes": {k: asdict(v) for k, v in mode_readiness(env).items()},
            }
        )

    @app.post("/api/scan")
    def start_scan(request: ScanRequest) -> JSONResponse:
        job = jobs.submit(request)
        return JSONResponse(job.public(), status_code=202)

    @app.get("/api/scan/{job_id}")
    def scan_status(job_id: str) -> JSONResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such scan")
        return JSONResponse(job.public())

    @app.get("/api/scans")
    def list_scans() -> JSONResponse:
        return JSONResponse([j.public() for j in jobs.list()])

    @app.get("/api/file")
    def get_file(path: str):
        """Serve a report/SARIF file, but only one an actual scan produced."""
        allowed: set[str] = set()
        for j in jobs.list():
            if j.sarif_path:
                allowed.add(j.sarif_path)
            allowed.update(j.report_paths or [])
        if path not in allowed:
            raise HTTPException(status_code=403, detail="not a result of any scan")
        if not Path(path).is_file():
            raise HTTPException(status_code=404, detail="file is gone")
        return FileResponse(path)

    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

    return app


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:  # pragma: no cover - runs a server
    """Run the control panel. Binds to localhost only by default."""
    _require()
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)
