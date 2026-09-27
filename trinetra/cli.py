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
from trinetra.brains import FileBrain
from trinetra.engines.base import registry
from trinetra.engines.dast.nuclei import NucleiAdapter
from trinetra.engines.dast.zap import ZapAdapter
from trinetra.engines.mobile.android import ApkStaticAdapter
from trinetra.engines.sast.semgrep import BUNDLED, SemgrepAdapter
from trinetra.engines.sca.sca_scanner import ScaScanner
from trinetra.learner import Learner, SandboxValidator, SemgrepRuleRunner
from trinetra.models.finding import Severity
from trinetra.models.scope import OutOfScopeError
from trinetra.orchestrator.pipeline import Pipeline, RunConfig
from trinetra.providers.anthropic import AnthropicProvider
from trinetra.providers.router import ProviderRouter
from trinetra.reporting.render import FORMATS, write_reports

app = typer.Typer(help="Trinetra — application security testing platform", no_args_is_help=True)
console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


BRAINS_ROOT = ".trinetra/brains"


def _learned_rules(disciplines: list[str]) -> dict:
    """Rules the learner promoted into each discipline's brain, so they run on every scan."""
    return {d: FileBrain(d, BRAINS_ROOT).load_rules() for d in disciplines}


def _register_default_engines(
    semgrep_configs: list[str] | None = None, disciplines: list[str] | None = None
) -> None:
    """Register the engines Trinetra ships with (source + target)."""
    names = {e.name for e in registry.all()}
    if "semgrep" not in names:
        registry.register(
            SemgrepAdapter(
                semgrep_configs or [BUNDLED],
                learned_rules=_learned_rules(disciplines or ["web"]),
            )
        )
    if "sca" not in names:
        registry.register(ScaScanner())
    if "zap" not in names:
        registry.register(ZapAdapter())
    if "nuclei" not in names:
        registry.register(NucleiAdapter())
    if "apk_static" not in names:
        registry.register(ApkStaticAdapter())


def _build_reviewer() -> AiReviewer:
    """Construct the AI reviewer for the configured provider (Anthropic first)."""
    provider = AnthropicProvider()
    return AiReviewer(ProviderRouter(provider))


def _build_learner(disciplines: list[str]) -> Learner:
    """Wire the self-evolving learner: a brain per discipline + the sandbox gate.

    The gate uses a local Semgrep runner; without Semgrep/Docker present it reports
    'skipped' and the loop promotes nothing (fail-closed).
    """
    brains_root = BRAINS_ROOT
    brains = {d: FileBrain(d, brains_root) for d in disciplines}
    validator = SandboxValidator(
        SemgrepRuleRunner(),
        positive_dir=f"{brains_root}/fixtures/vulnerable",
        negative_dir=f"{brains_root}/fixtures/remediated",
    )
    return Learner(brains, validator)


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
    apk: Annotated[
        str | None,
        typer.Option("--apk", help="Path to an Android .apk to scan statically"),
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
        list[str] | None,
        typer.Option(
            "--semgrep-config",
            help=(
                "Semgrep ruleset (repeatable). Default 'bundled' = Trinetra's offline rules. "
                "Add 'auto' or 'p/owasp-top-ten' for the online registry, or a local rules path."
            ),
        ),
    ] = None,
    ai: Annotated[
        bool,
        typer.Option("--ai/--no-ai", help="Run the AI cognitive pass (BYOK; needs an API key)"),
    ] = False,
    learn: Annotated[
        bool,
        typer.Option(
            "--learn/--no-learn", help="Self-evolving loop (needs Semgrep/Docker to promote)"
        ),
    ] = False,
    report: Annotated[
        list[str] | None,
        typer.Option("--report", help="Also write a report: exec | cert-in | crest (repeatable)"),
    ] = None,
) -> None:
    """Scan source (SAST+SCA), a URL (DAST), both (IAST), or an APK (Android) → SARIF."""
    if apk and (path or target):
        console.print("[bold red]--apk is its own scan; don't combine it with[/] --path/--target.")
        raise typer.Exit(code=2)
    if not path and not target and not apk:
        console.print("[bold red]Provide[/] --path[bold red],[/] --target[bold red], or[/] --apk.")
        raise typer.Exit(code=2)
    if target and not scope:
        console.print(
            "[bold red]Refused:[/] a --target (network) scan requires --scope pointing at a "
            "signed engagement manifest."
        )
        raise typer.Exit(code=2)
    bad = [r for r in (report or []) if r not in FORMATS]
    if bad:
        console.print(f"[bold red]Unknown report format(s):[/] {', '.join(bad)}. One of {FORMATS}.")
        raise typer.Exit(code=2)

    disciplines = discipline or (["android"] if apk else ["web"])
    _register_default_engines(semgrep_configs=semgrep_config, disciplines=disciplines)
    cfg = RunConfig(
        source_path=path,
        target_url=target,
        apk_path=apk,
        disciplines=disciplines,
        engines=engine,
        scope_manifest=scope,
    )
    pipeline = Pipeline(
        reviewer=_build_reviewer() if ai else None,
        learner=_build_learner(disciplines) if learn else None,
    )
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
    if learn:
        if result.rules_promoted:
            console.print(f"[cyan]Learner:[/] promoted {result.rules_promoted} new rule(s).")
        else:
            console.print(
                "[dim]Learner: no rules promoted (needs Semgrep + fixtures to validate; "
                "the gate is fail-closed).[/]"
            )
    if report:
        paths = write_reports(result.findings, result.run_dir, report)
        for p in paths:
            console.print(f"[green]Report written:[/] {p}")
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
