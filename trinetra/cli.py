"""Trinetra command-line interface.

    trinetra scan --path ./target --discipline web --discipline api

Phase 1 wires the deterministic engines (Semgrep SAST + SCA) into the pipeline and
writes a SARIF report. `--scope` enforces a signed engagement manifest.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from trinetra import __version__
from trinetra.engines.base import registry
from trinetra.engines.sast.semgrep import SemgrepAdapter
from trinetra.engines.sca.sca_scanner import ScaScanner
from trinetra.models.finding import Severity
from trinetra.models.scope import OutOfScopeError
from trinetra.orchestrator.pipeline import Pipeline, RunConfig

app = typer.Typer(help="Trinetra — application security testing platform", no_args_is_help=True)
console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _register_default_engines(semgrep_config: str = "auto") -> None:
    """Register the engines available in Phase 1."""
    if "semgrep" not in [e.name for e in registry.all()]:
        registry.register(SemgrepAdapter(config=semgrep_config))
        registry.register(ScaScanner())


@app.command()
def version() -> None:
    """Print the Trinetra version."""
    console.print(f"Trinetra {__version__}")


@app.command()
def scan(
    path: Annotated[str, typer.Option("--path", "-p", help="Source path to scan")],
    discipline: Annotated[
        list[str], typer.Option("--discipline", "-d", help="web | api (repeatable)")
    ] = None,
    scope: Annotated[
        str | None, typer.Option("--scope", help="Path to a signed scope manifest (YAML/JSON)")
    ] = None,
    engine: Annotated[
        list[str] | None, typer.Option("--engine", "-e", help="Limit to named engines")
    ] = None,
    semgrep_config: Annotated[
        str,
        typer.Option(
            "--semgrep-config",
            help="Semgrep ruleset: 'auto' (registry, needs network) or a local rules path",
        ),
    ] = "auto",
) -> None:
    """Run a deterministic scan (SAST + SCA) and write a SARIF report."""
    _register_default_engines(semgrep_config=semgrep_config)
    cfg = RunConfig(
        source_path=path,
        disciplines=discipline or ["web"],
        engines=engine,
        scope_manifest=scope,
    )
    pipeline = Pipeline()
    try:
        result = pipeline.run(cfg)
    except OutOfScopeError as exc:
        console.print(f"[bold red]Refused:[/] {exc}")
        raise typer.Exit(code=2) from exc

    _print_summary(result)
    console.print(f"\n[green]SARIF written:[/] {result.sarif_path}")
    if result.skipped_engines:
        console.print(
            f"[dim]Skipped (not installed here): {', '.join(result.skipped_engines)}[/]"
        )
    if result.failed_engines:
        console.print(
            f"[yellow]Engines that errored (see logs): {', '.join(result.failed_engines)}[/]"
        )


def _print_summary(result) -> None:
    table = Table(title=f"Trinetra findings ({len(result.findings)})")
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("Title")
    table.add_column("Location")
    for f in sorted(
        result.findings,
        key=lambda x: list(Severity).index(x.severity),
        reverse=True,
    ):
        style = _SEVERITY_STYLE.get(f.severity, "")
        loc = f.location.file or f.location.route or "-"
        if f.location.line:
            loc = f"{loc}:{f.location.line}"
        table.add_row(f"[{style}]{f.severity}[/]", f.source, f.title[:60], loc)
    console.print(table)


if __name__ == "__main__":
    app()
