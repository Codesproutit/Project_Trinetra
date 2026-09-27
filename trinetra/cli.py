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
from trinetra.ai import AiReviewer
from trinetra.engines.base import registry
from trinetra.engines.dast.nuclei import NucleiAdapter
from trinetra.engines.dast.zap import ZapAdapter
from trinetra.engines.sast.semgrep import SemgrepAdapter
from trinetra.engines.sca.sca_scanner import ScaScanner
from trinetra.models.finding import Severity
from trinetra.models.scope import OutOfScopeError
from trinetra.orchestrator.pipeline import Pipeline, RunConfig
from trinetra.providers.anthropic import AnthropicProvider
from trinetra.providers.router import ProviderRouter

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
    """Register the engines Trinetra ships with (source + target)."""
    names = {e.name for e in registry.all()}
    if "semgrep" not in names:
        registry.register(SemgrepAdapter(config=semgrep_config))
    if "sca" not in names:
        registry.register(ScaScanner())
    if "zap" not in names:
        registry.register(ZapAdapter())
    if "nuclei" not in names:
        registry.register(NucleiAdapter())


def _build_reviewer() -> AiReviewer:
    """Construct the AI reviewer for the configured provider (Anthropic first)."""
    provider = AnthropicProvider()
    return AiReviewer(ProviderRouter(provider))


@app.command()
def version() -> None:
    """Print the Trinetra version."""
    console.print(f"Trinetra {__version__}")


@app.command()
def scan(
    path: Annotated[
        str | None, typer.Option("--path", "-p", help="Source path to scan (SAST + SCA)")
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Running target URL to scan (DAST); needs --scope"),
    ] = None,
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
    ai: Annotated[
        bool,
        typer.Option("--ai/--no-ai", help="Run the AI cognitive pass (BYOK; needs an API key)"),
    ] = False,
) -> None:
    """Scan source (SAST+SCA), a target URL (DAST), or both (IAST) → SARIF report."""
    if not path and not target:
        console.print("[bold red]Provide[/] --path[bold red],[/] --target[bold red], or both.[/]")
        raise typer.Exit(code=2)
    if target and not scope:
        console.print(
            "[bold red]Refused:[/] a --target (network) scan requires --scope pointing at a "
            "signed engagement manifest."
        )
        raise typer.Exit(code=2)

    _register_default_engines(semgrep_config=semgrep_config)
    cfg = RunConfig(
        source_path=path,
        target_url=target,
        disciplines=discipline or ["web"],
        engines=engine,
        scope_manifest=scope,
    )
    pipeline = Pipeline(reviewer=_build_reviewer() if ai else None)
    try:
        result = pipeline.run(cfg)
    except OutOfScopeError as exc:
        console.print(f"[bold red]Refused:[/] {exc}")
        raise typer.Exit(code=2) from exc

    _print_summary(result)
    console.print(f"\n[green]SARIF written:[/] {result.sarif_path}")
    if result.verification_tasks:
        console.print(
            f"[cyan]IAST:[/] {result.verification_tasks} static sink(s) queued for verification; "
            f"{result.iast_confirmed} confirmed by the dynamic scan."
        )
    if result.ai_reviewed:
        console.print(
            f"[cyan]AI pass:[/] reviewed {result.ai_reviewed} finding(s), "
            f"dropped {result.ai_dropped} false positive(s); est. cost ${result.cost_usd:.4f}."
        )
    if "ai_reviewer" in result.skipped_engines:
        console.print(
            "[dim]AI pass skipped: no API key reachable. Set ANTHROPIC_API_KEY and "
            "install trinetra[llm], or drop --ai.[/]"
        )
    engines_skipped = [e for e in result.skipped_engines if e != "ai_reviewer"]
    if engines_skipped:
        console.print(
            f"[dim]Skipped (not installed here): {', '.join(engines_skipped)}[/]"
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
