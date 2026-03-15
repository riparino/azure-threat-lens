"""Azure Threat Lens – CLI entry point."""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import anyio
import click
from rich.console import Console

from azure_threat_lens import __version__
from azure_threat_lens.cli.output import (
    console,
    err_console,
    print_entity_result,
    print_header,
    print_identity_result,
    print_incident_list,
    print_triage_result,
)
from azure_threat_lens.config import get_settings
from azure_threat_lens.logging import configure_logging

# Lazy-import heavy modules inside commands to keep startup fast
_err = Console(stderr=True)


def _run(coro: Any) -> Any:
    """Run a coroutine synchronously, compatible with anyio."""
    return anyio.from_thread.run_sync(lambda: asyncio.run(coro))


# ── CLI root group ──────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="Azure Threat Lens")
@click.option("--log-level", default=None, help="Override log level (DEBUG/INFO/WARNING/ERROR)")
@click.option("--log-format", default=None, type=click.Choice(["console", "json"]), help="Log output format")
@click.option("--output", "-o", default=None, type=click.Choice(["rich", "json", "plain"]), help="Output format")
@click.pass_context
def cli(ctx: click.Context, log_level: str | None, log_format: str | None, output: str | None) -> None:
    """Azure Threat Lens – SOC investigation tool for Microsoft Sentinel and Azure.

    \b
    Configure credentials via environment variables or a .env file.
    Run 'atl <command> --help' for command-specific options.

    \b
    Examples:
      atl triage-incident --list
      atl triage-incident INC-001
      atl resolve-entity 8.8.8.8
      atl investigate-identity user@contoso.com
    """
    cfg = get_settings()
    effective_log_level = log_level or cfg.log_level
    effective_log_format = log_format or cfg.log_format
    configure_logging(level=effective_log_level, fmt=effective_log_format)

    ctx.ensure_object(dict)
    ctx.obj["output"] = output or cfg.output_format


# ── triage-incident ─────────────────────────────────────────────────────────

@cli.command("triage-incident")
@click.argument("incident_id", required=False)
@click.option("--list", "list_mode", is_flag=True, help="List and triage recent incidents")
@click.option("--lookback", default=72, show_default=True, help="Hours to look back when listing incidents")
@click.option("--severity", default=None, type=click.Choice(["High", "Medium", "Low", "Informational"]), help="Filter by severity")
@click.option("--top", default=20, show_default=True, help="Maximum incidents to return in list mode")
@click.option("--llm/--no-llm", "use_llm", default=True, show_default=True, help="Enable/disable LLM-assisted analysis")
@click.option("--workspace", default=None, help="Target a specific Sentinel workspace (name or ID) – supports Azure Lighthouse")
@click.pass_context
def triage_incident(
    ctx: click.Context,
    incident_id: str | None,
    list_mode: bool,
    lookback: int,
    severity: str | None,
    top: int,
    use_llm: bool,
    workspace: str | None,
) -> None:
    """Triage a Sentinel incident or list recent incidents ordered by risk.

    \b
    Examples:
      atl triage-incident INC-001-abc           # triage specific incident
      atl triage-incident --list                # list + triage last 72h
      atl triage-incident --list --severity High
      atl triage-incident INC-001 --no-llm -o json
      atl triage-incident --list --workspace "Client A – Production"
    """
    from azure_threat_lens.analysis.triage import IncidentTriageAnalyser
    from azure_threat_lens.llm.reasoning import LLMReasoner
    from azure_threat_lens.models.incident import Severity as SeverityEnum

    output_format: str = ctx.obj.get("output", "rich")

    if not list_mode and not incident_id:
        _err.print("[red]Error:[/red] provide an INCIDENT_ID or use --list")
        sys.exit(1)

    async def _run_triage() -> None:
        analyser = IncidentTriageAnalyser(workspace=workspace)
        llm = LLMReasoner() if use_llm else None

        if list_mode:
            print_header("Incident Triage", f"Last {lookback}h • top {top}")
            sev_filter = SeverityEnum(severity) if severity else None
            results = await analyser.triage_list(
                lookback_hours=lookback,
                severity=sev_filter,
                top=top,
            )
            if not results:
                console.print("[yellow]No incidents found matching criteria.[/yellow]")
                return
            print_incident_list(results, output_format)
        else:
            assert incident_id
            print_header(f"Triage: {incident_id}")
            result = await analyser.triage(incident_id)
            if llm and llm.is_available:
                result.llm_analysis = await llm.analyse_triage(result.model_dump())
            print_triage_result(result, output_format)

    try:
        asyncio.run(_run_triage())
    except KeyboardInterrupt:
        _err.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        _err.print(f"[red]Error:[/red] {exc}")
        if get_settings().log_level == "DEBUG":
            raise
        sys.exit(1)


# ── resolve-entity ──────────────────────────────────────────────────────────

@cli.command("resolve-entity")
@click.argument("identifier")
@click.option(
    "--kind",
    default=None,
    type=click.Choice(["Ip", "Host", "Account", "Url", "File", "FileHash", "AzureResource", "Unknown"]),
    help="Entity kind (auto-detected if omitted)",
)
@click.option("--llm/--no-llm", "use_llm", default=True, show_default=True, help="Enable/disable LLM analysis")
@click.pass_context
def resolve_entity(
    ctx: click.Context,
    identifier: str,
    kind: str | None,
    use_llm: bool,
) -> None:
    """Resolve and enrich an Azure entity (IP, hostname, resource ID, hash, URL).

    \b
    Examples:
      atl resolve-entity 198.51.100.42
      atl resolve-entity malicious-host.corp --kind Host
      atl resolve-entity /subscriptions/xxx/resourceGroups/rg1/...
      atl resolve-entity d41d8cd98f00b204e9800998ecf8427e --kind FileHash
    """
    from azure_threat_lens.analysis.entity import EntityResolver
    from azure_threat_lens.llm.reasoning import LLMReasoner
    from azure_threat_lens.models.entity import EntityKind

    output_format: str = ctx.obj.get("output", "rich")

    async def _run_resolve() -> None:
        resolver = EntityResolver()
        llm = LLMReasoner() if use_llm else None

        entity_kind = EntityKind(kind) if kind else None
        print_header(f"Resolve Entity: {identifier}")
        result = await resolver.resolve(identifier, kind=entity_kind)

        if llm and llm.is_available:
            result.llm_analysis = await llm.analyse_entity(result.model_dump())

        print_entity_result(result, output_format)

    try:
        asyncio.run(_run_resolve())
    except KeyboardInterrupt:
        _err.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        _err.print(f"[red]Error:[/red] {exc}")
        if get_settings().log_level == "DEBUG":
            raise
        sys.exit(1)


# ── investigate-identity ────────────────────────────────────────────────────

@cli.command("investigate-identity")
@click.argument("identifier")
@click.option("--lookback", default=30, show_default=True, help="Days of sign-in logs to analyse")
@click.option("--llm/--no-llm", "use_llm", default=True, show_default=True, help="Enable/disable LLM analysis")
@click.pass_context
def investigate_identity(
    ctx: click.Context,
    identifier: str,
    lookback: int,
    use_llm: bool,
) -> None:
    """Investigate an Entra ID user for signs of compromise or identity abuse.

    IDENTIFIER can be a UPN (user@contoso.com), email, or Entra ID object ID.

    \b
    Examples:
      atl investigate-identity alice@contoso.com
      atl investigate-identity alice@contoso.com --lookback 60
      atl investigate-identity 00000000-0000-0000-0000-000000000001 -o json
    """
    from azure_threat_lens.analysis.identity import IdentityInvestigator
    from azure_threat_lens.llm.reasoning import LLMReasoner

    output_format: str = ctx.obj.get("output", "rich")

    async def _run_investigate() -> None:
        investigator = IdentityInvestigator()
        llm = LLMReasoner() if use_llm else None

        print_header(f"Identity Investigation: {identifier}")
        result = await investigator.investigate(identifier, lookback_days=lookback)

        if llm and llm.is_available:
            result.llm_analysis = await llm.analyse_identity(result.model_dump())

        print_identity_result(result, output_format)

    try:
        asyncio.run(_run_investigate())
    except KeyboardInterrupt:
        _err.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        _err.print(f"[red]Error:[/red] {exc}")
        if get_settings().log_level == "DEBUG":
            raise
        sys.exit(1)


# ── config check ────────────────────────────────────────────────────────────

@cli.command("check-config")
def check_config() -> None:
    """Show current configuration and connectivity status."""
    from rich.table import Table
    from rich import box as rich_box

    cfg = get_settings()
    console.print()
    print_header("Azure Threat Lens – Configuration Check", f"v{__version__}")

    table = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    def _status(ok: bool, detail: str = "") -> tuple[str, str]:
        return ("[green]✓ Configured[/green]" if ok else "[red]✗ Missing[/red]", detail)

    az_ok = cfg.is_azure_configured
    table.add_row("Azure Identity", *_status(az_ok, cfg.azure.tenant_id[:8] + "..." if az_ok else "Set ATL_AZURE_TENANT_ID + ATL_AZURE_CLIENT_ID"))

    sentinel_ok = bool(cfg.sentinel.workspace_name)
    table.add_row("Sentinel", *_status(sentinel_ok, cfg.sentinel.workspace_name or "Set ATL_SENTINEL_WORKSPACE_NAME"))

    table.add_row("Defender XDR", *_status(cfg.defender.enabled, "Enabled" if cfg.defender.enabled else "Set ATL_DEFENDER_ENABLED=true"))

    llm_ok = cfg.is_llm_configured
    table.add_row("Claude LLM", *_status(llm_ok, cfg.llm.model if llm_ok else "Set ATL_ANTHROPIC_API_KEY"))

    table.add_row("VirusTotal", *_status(cfg.threat_intel.virustotal_enabled, "Active" if cfg.threat_intel.virustotal_enabled else "Optional – set ATL_VIRUSTOTAL_API_KEY"))
    table.add_row("GreyNoise", *_status(cfg.threat_intel.greynoise_enabled, "Active" if cfg.threat_intel.greynoise_enabled else "Optional – set ATL_GREYNOISE_API_KEY"))
    table.add_row("AbuseIPDB", *_status(cfg.threat_intel.abuseipdb_enabled, "Active" if cfg.threat_intel.abuseipdb_enabled else "Optional – set ATL_ABUSEIPDB_API_KEY"))

    console.print(table)
    console.print(f"\n  Log level:    [cyan]{cfg.log_level}[/cyan]")
    console.print(f"  Output format: [cyan]{cfg.output_format}[/cyan]")
    console.print(f"  Config file:   [cyan]{cfg.config_file}[/cyan]\n")


if __name__ == "__main__":
    cli()
