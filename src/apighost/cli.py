"""
APIGhost CLI — Typer + Rich Command-Line Interface

The user-facing entry point that ties all components together:
    Spec Parser → Chain Builder → Data Generator → Executor → Verdict Engine

Commands:
    apighost scan   — Full BOLA scan against a live API
    apighost chains — Parse spec and display discovered chains (dry run)
    apighost version — Display version info
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Force UTF-8 on Windows to prevent cp1252 encoding crashes with Rich + emoji
if sys.platform == "win32":
    import os
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich import box

from apighost.parser import SpecParser, SpecParserError
from apighost.chain_builder import ChainBuilder
from apighost.models import ChainSource, Verdict
from apighost import __version__

app = typer.Typer(
    name="apighost",
    help="APIGhost — Stateful BOLA Detection Engine",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=False, # We'll handle this manually to show the banner
)
console = Console()

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Display APIGhost version information."
    ),
):
    """
    APIGhost — Stateful BOLA Detection Engine
    """
    if version:
        _print_banner()
        console.print(f"[bold green]APIGhost[/bold green] version {__version__}")
        raise typer.Exit()
        
    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print(ctx.get_help())
        raise typer.Exit()
# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────

BANNER = r"""
    _    ____ ___  ____  _               _
   / \  |  _ \_ _|/ ___|| |__   ___  ___| |_
  / _ \ | |_) | || |  _ | '_ \ / _ \/ __| __|
 / ___ \|  __/| || |_| || | | | (_) \__ \ |_
/_/   \_\_|  |___|\____||_| |_|\___/|___/\__|
"""

TAGLINE = "Stateful BOLA Detection Engine — Cross-User Authorization Testing"


def _print_banner() -> None:
    """Display the APIGhost banner."""
    console.print(
        Panel(
            Text(BANNER, style="bold cyan") + Text(f"\n  {TAGLINE}", style="dim"),
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ─────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
        force=True,
    )


# ─────────────────────────────────────────────
# Chain Discovery Command
# ─────────────────────────────────────────────

@app.command()
def chains(
    spec: str = typer.Option(
        ..., "--spec", "-s",
        help="Path to OpenAPI specification file (YAML/JSON)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging",
    ),
) -> None:
    """
    Parse an OpenAPI spec and display discovered attack chains.

    This is a dry-run mode — no HTTP requests are made. Useful for
    verifying that the Chain Builder correctly identifies CRUD
    dependencies before running a live scan.
    """
    _setup_logging(verbose)
    _print_banner()

    # ── Parse Spec ──
    spec_path = Path(spec)
    if not spec_path.exists():
        console.print(f"[bold red]Error:[/] Spec file not found: {spec_path}")
        raise typer.Exit(code=1)

    with console.status("[bold cyan]Parsing OpenAPI specification...", spinner="dots"):
        try:
            parser = SpecParser(spec_path)
            resolved = parser.parse()
        except SpecParserError as e:
            console.print(f"[bold red]Parse Error:[/] {e}")
            raise typer.Exit(code=1)

    # ── Build Chains ──
    with console.status("[bold cyan]Building attack chains...", spinner="dots"):
        builder = ChainBuilder(resolved)
        attack_chains = builder.build_chains()

    # ── Display Results ──
    console.print()

    # Endpoint summary
    ep_table = Table(
        title="📡 Extracted Endpoints",
        box=box.ROUNDED,
        title_style="bold white",
        show_lines=False,
    )
    ep_table.add_column("Method", style="bold", width=8)
    ep_table.add_column("Path", style="cyan")
    ep_table.add_column("Operation ID", style="dim")
    ep_table.add_column("CRUD Role", style="yellow")

    for ep in builder.endpoints:
        method_style = {
            "GET": "green", "POST": "blue",
            "PUT": "yellow", "PATCH": "yellow",
            "DELETE": "red",
        }.get(ep.method.value, "white")

        ep_table.add_row(
            f"[{method_style}]{ep.method.value}[/]",
            ep.path,
            ep.operation_id or "—",
            ep.crud_role.value,
        )

    console.print(ep_table)
    console.print()

    if not attack_chains:
        console.print(
            "[bold yellow]⚠ No attack chains discovered.[/] "
            "The spec may not have matching CREATE+READ pairs."
        )
        return

    # Chain table
    chain_table = Table(
        title="🔗 Discovered Attack Chains",
        box=box.ROUNDED,
        title_style="bold white",
        show_lines=True,
    )
    chain_table.add_column("ID", style="bold cyan", width=12)
    chain_table.add_column("Resource", style="bold white")
    chain_table.add_column("Layer", width=18)
    chain_table.add_column("Variant", style="magenta")
    chain_table.add_column("CREATE", style="blue")
    chain_table.add_column("ATTACK", style="green")
    chain_table.add_column("DELETE", style="red")
    chain_table.add_column("ID Field", style="yellow")
    chain_table.add_column("Confidence", justify="right")

    for chain in attack_chains:
        layer = (
            "[green]Layer 1 (Path)[/]"
            if chain.source == ChainSource.LAYER1_PATH
            else "[yellow]Layer 2 (Schema)[/]"
        )
        conf_color = "green" if chain.confidence >= 0.8 else "yellow"

        attack_str = f"{chain.attack.method.value} {chain.attack.path}" if hasattr(chain, 'attack') and chain.attack else f"GET {chain.read.path}"
        chain_table.add_row(
            chain.chain_id,
            chain.resource_name,
            layer,
            chain.variant.value,
            f"POST {chain.create.path}",
            attack_str,
            f"DELETE {chain.delete.path}" if chain.delete else "[dim]None[/]",
            ", ".join(chain.id_fields),
            f"[{conf_color}]{chain.confidence:.0%}[/]",
        )

    console.print(chain_table)
    console.print()

    # Summary stats
    l1 = sum(1 for c in attack_chains if c.source == ChainSource.LAYER1_PATH)
    l2 = sum(1 for c in attack_chains if c.source == ChainSource.LAYER2_SCHEMA)
    console.print(
        f"  📊 [bold]{len(builder.endpoints)}[/] endpoints → "
        f"[bold]{len(attack_chains)}[/] chains "
        f"([green]{l1} Layer 1[/], [yellow]{l2} Layer 2[/])"
    )
    console.print()


# ─────────────────────────────────────────────
# Full Scan Command
# ─────────────────────────────────────────────

@app.command()
def scan(
    spec: str = typer.Option(
        ..., "--spec", "-s",
        help="Path to OpenAPI specification file (YAML/JSON)",
    ),
    target: str = typer.Option(
        ..., "--target", "-t",
        help="Base URL of the target API (e.g., http://localhost:8888)",
    ),
    token_a: str = typer.Option(
        ..., "--token-a",
        help="Bearer token for User A (resource owner)",
    ),
    token_b: str = typer.Option(
        ..., "--token-b",
        help="Bearer token for User B (attacker)",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file path for the report",
    ),
    report_format: str = typer.Option(
        "json", "--format", "-f",
        help="Report format: json, html, md, sarif",
    ),
    rate: float = typer.Option(
        10.0, "--rate", "-r",
        help="Max requests per second (rate limiter)",
    ),
    concurrent: int = typer.Option(
        5, "--concurrent", "-c",
        help="Max concurrent requests (semaphore)",
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify",
        help="Disable SSL certificate verification",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Show generated payloads and chain plan without sending requests",
    ),
    auth_mode: str = typer.Option(
        "bearer", "--auth-mode",
        help="Authentication mode: bearer, api_key, cookie, basic, custom",
    ),
    auth_header: str = typer.Option(
        "Authorization", "--auth-header",
        help="Header name for API key or custom auth (e.g., X-API-Key)",
    ),
    refresh_cmd: Optional[str] = typer.Option(
        None, "--refresh-cmd",
        help="Shell command to refresh expired tokens (receives 'a' or 'b' as argument)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging",
    ),
    aggressive: bool = typer.Option(
        False, "--aggressive",
        help="Enable aggressive tests (Rate Limiting, Injection)",
    ),
    burst: int = typer.Option(
        50, "--burst",
        help="Number of concurrent requests for rate limit testing"
    ),
    canaries: str = typer.Option(
        None, "--canaries",
        help="JSON string of mass assignment canaries"
    ),
) -> None:
    """
    Execute a full BOLA scan against a live API.

    This command parses the OpenAPI spec, discovers attack chains,
    generates valid payloads, executes cross-user authorization
    tests, and produces a verdict for each chain.

    Requires two valid bearer tokens for different user accounts.
    """
    _setup_logging(verbose)
    _print_banner()

    # Import here to avoid circular dependency at CLI parse time
    from apighost.executor import ChainExecutor, ExecutorConfig
    from apighost.verdict import VerdictEngine

    # ── Phase 1: Parse Spec ──
    spec_path = Path(spec)
    if not spec_path.exists():
        console.print(f"[bold red]Error:[/] Spec file not found: {spec_path}")
        raise typer.Exit(code=1)

    console.print("\n[bold cyan]Phase 1:[/] Parsing OpenAPI specification...")
    try:
        parser = SpecParser(spec_path)
        resolved = parser.parse()
    except SpecParserError as e:
        console.print(f"[bold red]Parse Error:[/] {e}")
        raise typer.Exit(code=1)

    console.print(f"  ✅ Parsed {len(resolved.get('paths', {}))} paths\n")

    # ── Phase 2: Build Chains ──
    console.print("[bold cyan]Phase 2:[/] Building attack chains...")
    builder = ChainBuilder(resolved)
    attack_chains = builder.build_chains()

    if not attack_chains:
        console.print(
            "[bold yellow]⚠ No attack chains discovered.[/] Nothing to scan."
        )
        raise typer.Exit(code=0)

    l1 = sum(1 for c in attack_chains if c.source == ChainSource.LAYER1_PATH)
    l2 = sum(1 for c in attack_chains if c.source == ChainSource.LAYER2_SCHEMA)
    console.print(
        f"  ✅ {len(attack_chains)} chains discovered "
        f"({l1} Layer 1, {l2} Layer 2)\n"
    )

    if dry_run:
        from apighost.generator import DataGenerator, DependencyPrefetcher
        data_gen = DataGenerator(resolved)
        for chain in attack_chains:
            payload = data_gen.generate_payload(chain.create)
            console.print(Panel(
                json.dumps(payload, indent=2) if payload else "{}",
                title=f"Payload: {chain.chain_id}",
                border_style="green"
            ))
        raise typer.Exit(code=0)

    # ── Phase 3: Execute Chains ──
    console.print("[bold cyan]Phase 3:[/] Executing cross-user attack chains...")
    console.print(f"  🎯 Target: {target}")
    console.print(f"  🔒 Rate: {rate} req/s, Concurrency: {concurrent}\n")

    from apighost.models import AuthMode
    try:
        mode = AuthMode(auth_mode.lower())
    except ValueError:
        console.print(f"[bold red]Error:[/] Invalid auth mode: {auth_mode}")
        console.print("Valid modes: bearer, api_key, cookie, basic, custom")
        raise typer.Exit(code=2)

    canaries_dict = None
    if canaries:
        try:
            canaries_dict = json.loads(canaries)
        except json.JSONDecodeError:
            console.print("[bold red]Error:[/] Invalid JSON for canaries")
            raise typer.Exit(code=1)

    executor_config = ExecutorConfig(
        base_url=target,
        token_a=token_a,
        token_b=token_b,
        auth_mode=mode,
        auth_header=auth_header,
        token_refresh_cmd=refresh_cmd,
        requests_per_second=rate,
        max_concurrent=concurrent,
        verify_ssl=not no_verify,
        aggressive=aggressive,
        burst=burst,
        canaries=canaries_dict,
    )
    executor = ChainExecutor(executor_config, resolved)

    # Run async execution
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(attack_chains))

        async def _run():
            # execute_all handles client lifecycle, Tier 3 prefetching,
            # and the Dead Letter Queue final sweep.
            return await executor.execute_all(
                attack_chains,
                progress_callback=lambda: progress.advance(task),
            )

        results = asyncio.run(_run())

    # ── Phase 4: Verdict Engine ──
    console.print("\n[bold cyan]Phase 4:[/] Analyzing results with Verdict Engine...")
    verdict_engine = VerdictEngine()
    results = verdict_engine.evaluate_all(results)

    # ── Display Results ──
    _display_results(results)

    # ── Save Report ──
    if output:
        from apighost.reporter import Reporter
        reporter = Reporter(results)
        reporter.save(output, format=report_format)
        console.print(f"\n  💾 Report saved to: [cyan]{output}[/]")

    # ── Summary ──
    _display_summary(results)

    # CI/CD exit codes
    confirmed = sum(1 for r in results if r.verdict == Verdict.CONFIRMED)
    likely = sum(1 for r in results if r.verdict == Verdict.LIKELY)
    if confirmed > 0 or likely > 0:
        raise typer.Exit(code=1)


# ─────────────────────────────────────────────
# Result Display
# ─────────────────────────────────────────────

def _display_results(results: list) -> None:
    """Display a rich table of scan results."""
    console.print()

    table = Table(
        title="🔍 BOLA Scan Results",
        box=box.HEAVY_HEAD,
        title_style="bold white",
        show_lines=True,
    )
    table.add_column("Chain", style="cyan", width=12)
    table.add_column("Resource", style="bold")
    table.add_column("Variant", style="magenta")
    table.add_column("Verdict", width=14)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Owner", justify="center", width=6)
    table.add_column("Attacker", justify="center", width=8)
    table.add_column("Duration", justify="right", width=10)

    for result in results:
        verdict_style = {
            Verdict.CONFIRMED: "bold red",
            Verdict.LIKELY: "bold yellow",
            Verdict.POSSIBLE: "dim yellow",
            Verdict.SECURE: "bold green",
            Verdict.ERROR: "bold magenta",
        }.get(result.verdict, "white")

        verdict_icon = {
            Verdict.CONFIRMED: "🔴 CONFIRMED",
            Verdict.LIKELY: "🟡 LIKELY",
            Verdict.POSSIBLE: "🟠 POSSIBLE",
            Verdict.SECURE: "🟢 SECURE",
            Verdict.ERROR: "⚪ ERROR",
        }.get(result.verdict, result.verdict.value)

        table.add_row(
            result.chain.chain_id,
            result.chain.resource_name,
            result.chain.variant.value,
            f"[{verdict_style}]{verdict_icon}[/]",
            f"[{verdict_style}]{result.score:.2f}[/]",
            str(result.read_as_owner_status),
            str(result.read_as_attacker_status),
            f"{result.duration_ms}ms",
        )

    console.print(table)

    # Signal breakdown for non-SECURE results
    interesting = [r for r in results if r.verdict != Verdict.SECURE and r.signals]
    if interesting:
        console.print()
        console.print("[bold]Signal Breakdown:[/]")
        for result in interesting:
            console.print(f"\n  [cyan]{result.chain.chain_id}[/] ({result.chain.resource_name}):")
            for signal_name, signal_value in result.signals.items():
                bar_len = int(signal_value * 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                color = "red" if signal_value > 0.7 else "yellow" if signal_value > 0.3 else "green"
                console.print(f"    {signal_name:<25} [{color}]{bar}[/] {signal_value:.2f}")


def _display_summary(results: list) -> None:
    """Display scan summary statistics."""
    console.print()

    total = len(results)
    confirmed = sum(1 for r in results if r.verdict == Verdict.CONFIRMED)
    likely = sum(1 for r in results if r.verdict == Verdict.LIKELY)
    possible = sum(1 for r in results if r.verdict == Verdict.POSSIBLE)
    secure = sum(1 for r in results if r.verdict == Verdict.SECURE)
    errors = sum(1 for r in results if r.verdict == Verdict.ERROR)

    summary = Panel(
        f"  Total Chains Tested:  [bold]{total}[/]\n"
        f"  [bold red]🔴 CONFIRMED BOLA:[/]     [bold red]{confirmed}[/]\n"
        f"  [bold yellow]🟡 LIKELY BOLA:[/]        [bold yellow]{likely}[/]\n"
        f"  [dim yellow]🟠 POSSIBLE BOLA:[/]      {possible}\n"
        f"  [bold green]🟢 SECURE:[/]             [bold green]{secure}[/]\n"
        f"  [dim]⚪ ERRORS:[/]              {errors}",
        title="📊 Scan Summary",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(summary)

    if confirmed > 0:
        console.print(
            "[bold red]⚠  BOLA vulnerabilities confirmed! "
            "Immediate remediation required.[/]\n"
        )
    elif likely > 0:
        console.print(
            "[bold yellow]⚠  Likely BOLA detected. "
            "Manual verification recommended.[/]\n"
        )
    else:
        console.print(
            "[bold green]✅ No BOLA vulnerabilities detected.[/]\n"
        )


# ─────────────────────────────────────────────
# Import Command
# ─────────────────────────────────────────────

@app.command(name="import")
def import_traffic(
    filepath: str = typer.Argument(..., help="Path to HAR or Burp XML file"),
    format: str = typer.Option("har", "--format", "-f", help="Format: har or burp"),
    output: str = typer.Option("imported_spec.json", "--output", "-o", help="Output spec file path"),
) -> None:
    """Import HAR or Burp traffic logs to generate an APIGhost spec."""
    from apighost.importer import TrafficImporter
    
    console.print(f"[bold blue]APIGhost Traffic Importer[/]")
    console.print(f"Reading {format.upper()} file: {filepath}")
    
    importer = TrafficImporter()
    
    try:
        if format.lower() == "har":
            spec = importer.import_har(filepath)
        elif format.lower() == "burp":
            spec = importer.import_burp_xml(filepath)
        else:
            console.print(f"[bold red]Error:[/] Unsupported format: {format}")
            raise typer.Exit(1)
            
        with open(output, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
            
        endpoints_count = sum(len(methods) for methods in spec.get("paths", {}).values())
        console.print(f"[bold green]Success![/] Imported {endpoints_count} endpoints.")
        console.print(f"Spec saved to: {output}")
        console.print(f"\nYou can now run: apighost chains --spec {output}")
        
    except Exception as e:
        console.print(f"[bold red]Error importing file:[/] {e}")
        raise typer.Exit(1)




# ─────────────────────────────────────────────
# Version Command
# ─────────────────────────────────────────────

@app.command()
def version() -> None:
    """Display APIGhost version information."""
    console.print(f"[bold cyan]APIGhost[/] v{__version__}")
    console.print("Stateful BOLA Detection Engine")
    console.print("https://github.com/Arul-AGC/APIGhost")


# ─────────────────────────────────────────────
# Crawler Command
# ─────────────────────────────────────────────

@app.command(name="crawl")
def crawl(
    base_url: str = typer.Argument(..., help="Base URL of the target API"),
    wordlist: str = typer.Argument(..., help="Path to a wordlist file"),
    output: str = typer.Option("spec.json", "--output", "-o", help="Output spec file path"),
) -> None:
    """Spec-less auto-discovery crawler."""
    from apighost.crawler import APICrawler
    
    console.print(f"[bold blue]APIGhost Spec-less Crawler[/]")
    
    path_path = Path(wordlist)
    if not path_path.exists():
        console.print(f"[bold red]Error:[/] Wordlist not found: {wordlist}")
        raise typer.Exit(code=1)
        
    words = path_path.read_text(encoding="utf-8").splitlines()
    words = [w.strip() for w in words if w.strip()]
    
    crawler = APICrawler(base_url, words)
    spec = asyncio.run(crawler.crawl())
    
    with open(output, "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2)
        
    console.print(f"[bold green]Success![/] Crawled and saved spec to {output}")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app()
