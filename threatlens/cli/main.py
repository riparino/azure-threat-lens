"""threatlens CLI entry point."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import click

from threatlens.utils.logging import configure_logging


def _run(coro: object) -> None:
    """Run a coroutine in the event loop, handling KeyboardInterrupt cleanly."""
    try:
        asyncio.run(coro)  # type: ignore[arg-type]
    except KeyboardInterrupt:
        click.echo("\nAborted.", err=True)
        sys.exit(1)


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(package_name="threatlens")
@click.option(
    "--log-level",
    default="INFO",
    envvar="ATL_LOG_LEVEL",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Log verbosity.",
)
@click.option(
    "--log-format",
    default="console",
    envvar="ATL_LOG_FORMAT",
    type=click.Choice(["console", "json"], case_sensitive=False),
    help="Log output format.",
)
@click.option(
    "--output",
    "-o",
    "output_format",
    default="rich",
    envvar="ATL_OUTPUT_FORMAT",
    type=click.Choice(["rich", "json", "plain"], case_sensitive=False),
    help="Output format.",
)
@click.pass_context
def cli(ctx: click.Context, log_level: str, log_format: str, output_format: str) -> None:
    """Azure Threat Lens – SOC investigation toolkit for Microsoft Sentinel."""
    configure_logging(level=log_level, fmt=log_format)
    ctx.ensure_object(dict)
    ctx.obj["output_format"] = output_format
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ── triage-incident ────────────────────────────────────────────────────────────

@cli.command("triage-incident")
@click.argument("incident_id")
@click.option(
    "--workspace", "-w",
    default=None,
    help="Sentinel workspace name or ID (uses default if omitted).",
)
@click.option(
    "--llm/--no-llm",
    default=False,
    help="Enhance the investigation with Azure OpenAI analysis.",
)
@click.pass_context
def triage_incident(
    ctx: click.Context,
    incident_id: str,
    workspace: str | None,
    llm: bool,
) -> None:
    """Triage a Sentinel incident and produce a full investigation report.

    INCIDENT_ID is the Sentinel incident number or GUID.

    Example:
      threatlens triage-incident 12345
      threatlens triage-incident 12345 --workspace my-sentinel-ws --llm
    """
    from threatlens.cli.commands import _triage_incident

    output_format = ctx.obj.get("output_format", "rich")
    _run(_triage_incident(incident_id, workspace, output_format, llm))


# ── resolve-entity ─────────────────────────────────────────────────────────────

@cli.command("resolve-entity")
@click.argument("identifier")
@click.pass_context
def resolve_entity(ctx: click.Context, identifier: str) -> None:
    """Resolve and enrich an Azure entity with threat intelligence and context.

    IDENTIFIER can be an IP address, hostname, UPN, ARM resource ID, URL, or file hash.

    Examples:
      threatlens resolve-entity 1.2.3.4
      threatlens resolve-entity user@contoso.com
      threatlens resolve-entity /subscriptions/abc/resourceGroups/rg/providers/…
    """
    from threatlens.cli.commands import _resolve_entity

    output_format = ctx.obj.get("output_format", "rich")
    _run(_resolve_entity(identifier, output_format))


# ── investigate-identity ───────────────────────────────────────────────────────

@cli.command("investigate-identity")
@click.argument("identifier")
@click.option(
    "--days", "-d",
    default=7,
    show_default=True,
    help="Lookback window in days for sign-in and audit log analysis.",
)
@click.pass_context
def investigate_identity(
    ctx: click.Context,
    identifier: str,
    days: int,
) -> None:
    """Investigate a user identity for signs of compromise or abuse.

    IDENTIFIER is a UPN (user@domain), object ID, or account name.

    Examples:
      threatlens investigate-identity alice@contoso.com
      threatlens investigate-identity alice@contoso.com --days 14
    """
    from threatlens.cli.commands import _investigate_identity

    output_format = ctx.obj.get("output_format", "rich")
    _run(_investigate_identity(identifier, days, output_format))


# ── investigate-resource ───────────────────────────────────────────────────────

@cli.command("investigate-resource")
@click.argument("resource_id")
@click.option(
    "--hours", "-H",
    default=48,
    show_default=True,
    help="Lookback window in hours for Activity Log analysis.",
)
@click.pass_context
def investigate_resource(
    ctx: click.Context,
    resource_id: str,
    hours: int,
) -> None:
    """Investigate an Azure resource for anomalous access patterns.

    RESOURCE_ID is the full ARM resource ID.

    Example:
      threatlens investigate-resource /subscriptions/abc/resourceGroups/rg/providers/…
    """
    from threatlens.cli.commands import _investigate_resource

    output_format = ctx.obj.get("output_format", "rich")
    _run(_investigate_resource(resource_id, hours, output_format))


# ── breachmanager ──────────────────────────────────────────────────────────────

@cli.command("breachmanager")
@click.option(
    "--scenario",
    required=True,
    help="Free-form breach scenario text (or incident summary) for breach-manager planning.",
)
@click.option(
    "--incident-json",
    default=None,
    help="Optional JSON payload for incident context (title/description/severity/entities).",
)
@click.option(
    "--mode",
    default="reactive",
    show_default=True,
    type=click.Choice(["reactive", "proactive"], case_sensitive=False),
    help="Planning mode for breach manager.",
)
@click.option(
    "--auth-strategy",
    default="service_principal",
    show_default=True,
    type=click.Choice(["service_principal", "user"], case_sensitive=False),
    help="Credential strategy used to execute triage/remediation steps.",
)
@click.option(
    "--tenant-id",
    "tenant_ids",
    multiple=True,
    help="Target tenant ID; repeat for multi-tenant operations.",
)
@click.option(
    "--lighthouse/--no-lighthouse",
    default=False,
    help="Mark operation as Azure Lighthouse delegated cross-tenant execution.",
)
@click.pass_context
def breachmanager(
    ctx: click.Context,
    scenario: str,
    incident_json: str | None,
    mode: str,
    auth_strategy: str,
    tenant_ids: tuple[str, ...],
    lighthouse: bool,
) -> None:
    """Breach manager planner for enterprise Azure multi-tenant incidents.

    Examples:
      threatlens breachmanager --scenario "AKS workload compromised and secrets exfiltrated"
      threatlens breachmanager --scenario "Suspicious role assignments" --tenant-id <tenant> --lighthouse
    """
    from threatlens.cli.commands import _breachmanager

    output_format = ctx.obj.get("output_format", "rich")
    _run(
        _breachmanager(
            scenario,
            incident_json,
            mode,
            auth_strategy,
            tenant_ids,
            lighthouse,
            output_format,
        )
    )


@cli.command("setup")
@click.option(
    "--mode",
    default=None,
    type=click.Choice(["dev", "prod"], case_sensitive=False),
    help="Setup mode: dev stores secrets locally, prod uses Azure Key Vault.",
)
@click.option(
    "--env-file",
    default=".env",
    show_default=True,
    help="Environment file path to write.",
)
def setup(mode: str | None, env_file: str) -> None:
    """Guided setup for development or production deployments.

    - dev: writes local secrets to .env with restrictive file permissions
    - prod: writes key vault pointers and non-secret metadata to .env
    """

    selected = mode or click.prompt("Setup mode", type=click.Choice(["dev", "prod"]))
    env_values: dict[str, str] = {}

    click.echo("\nAzure baseline settings")
    env_values["ATL_AZURE_TENANT_ID"] = click.prompt("Tenant ID", default="", show_default=False)
    env_values["ATL_AZURE_CLIENT_ID"] = click.prompt("Client ID (app registration)", default="", show_default=False)
    env_values["ATL_AZURE_SUBSCRIPTION_ID"] = click.prompt(
        "Subscription ID", default="", show_default=False
    )
    env_values["ATL_AZURE_AUTH_MODE"] = click.prompt(
        "Auth mode", type=click.Choice(["service_principal", "user"]), default="service_principal"
    )

    env_values["ATL_SENTINEL_WORKSPACE_ID"] = click.prompt(
        "Sentinel workspace ID", default="", show_default=False
    )
    env_values["ATL_SENTINEL_WORKSPACE_NAME"] = click.prompt(
        "Sentinel workspace name", default="", show_default=False
    )
    env_values["ATL_SENTINEL_RESOURCE_GROUP"] = click.prompt(
        "Sentinel resource group", default="", show_default=False
    )

    if selected == "dev":
        click.echo("\nDevelopment mode: storing secrets locally in env file.")
        env_values["ATL_SECRET_SOURCE"] = "local"
        env_values["ATL_AZURE_CLIENT_SECRET"] = click.prompt(
            "Client secret", hide_input=True, default="", show_default=False
        )
        env_values["ATL_OPENAI_API_KEY"] = click.prompt(
            "Optional OpenAI API key", hide_input=True, default="", show_default=False
        )
        env_values["ATL_ANTHROPIC_API_KEY"] = click.prompt(
            "Optional Anthropic API key", hide_input=True, default="", show_default=False
        )
    else:
        click.echo("\nProduction mode: secrets must come from Azure Key Vault.")
        env_values["ATL_SECRET_SOURCE"] = "keyvault"
        env_values["ATL_KEYVAULT_URI"] = click.prompt(
            "Key Vault URI (https://<name>.vault.azure.net)",
            default="",
            show_default=False,
        )
        env_values["ATL_KEYVAULT_SECRET_MAP"] = click.prompt(
            "Optional JSON secret map (setting path -> key vault secret name)",
            default="{}",
            show_default=True,
        )

    content = "\n".join(f"{k}={v}" for k, v in env_values.items()) + "\n"
    path = Path(env_file)
    path.write_text(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    click.echo(f"\nWrote setup to {path}.")
    if selected == "prod":
        click.echo("Ensure this identity has GET secret access on the configured Key Vault.")
