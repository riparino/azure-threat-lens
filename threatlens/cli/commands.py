"""CLI command implementations for threatlens."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import click
from rich.console import Console
from rich.json import JSON
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


# ── Output helpers ─────────────────────────────────────────────────────────────

def _output(data: Any, *, output_format: str, title: str = "") -> None:
    """Render data in the requested output format."""
    if output_format == "json":
        click.echo(json.dumps(data, indent=2, default=str))
    elif output_format == "plain":
        click.echo(json.dumps(data, default=str))
    else:  # rich
        if isinstance(data, dict):
            console.print(Panel(JSON(json.dumps(data, default=str)), title=title or "Result"))
        else:
            console.print(data)


def _err(msg: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {msg}", file=sys.stderr)


def _section(title: str) -> None:
    console.rule(f"[bold cyan]{title}[/bold cyan]")


# ── triage-incident ────────────────────────────────────────────────────────────

async def _triage_incident(
    incident_id: str,
    workspace: str | None,
    output_format: str,
    use_llm: bool,
) -> None:
    from threatlens.core.investigation_engine import InvestigationEngine, InvestigationConfig

    cfg = InvestigationConfig(
        run_identity_analysis=True,
        run_resource_analysis=True,
        run_privilege_analysis=True,
        run_token_analysis=True,
        run_defender=True,
        use_llm=use_llm,
    )
    engine = InvestigationEngine(cfg)
    with console.status(f"[bold green]Investigating incident {incident_id}…"):
        report = await engine.run(incident_id, workspace=workspace)

    report_dict = report.to_dict()

    if output_format == "json":
        click.echo(json.dumps(report_dict, indent=2, default=str))
        return

    # Rich output
    triage = report_dict.get("triage", {})
    verdict = report_dict.get("verdict", {})

    _section(f"Incident Triage: {incident_id}")

    # Risk level badge
    risk_colours = {
        "critical": "bold red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold green",
        "informational": "dim",
    }
    rl = triage.get("risk_level", "unknown")
    console.print(f"Risk Level: [{risk_colours.get(rl, 'white')}]{rl.upper()}[/]")
    console.print(f"Confidence: {triage.get('confidence', 0):.0%}\n")
    console.print(Panel(triage.get("summary", "No summary available"), title="Summary"))

    # Key entities table
    key_entities: list[dict[str, Any]] = triage.get("key_entities", [])
    if key_entities:
        t = Table("Kind", "Identifier", "Risk Indicators", box=box.SIMPLE)
        for e in key_entities[:15]:
            t.add_row(
                e.get("kind", "?"),
                e.get("identifier", "?"),
                "; ".join(e.get("risk_indicators", [])) or "—",
            )
        console.print(t)

    # Attack hypotheses
    hypotheses: list[dict[str, Any]] = triage.get("attack_hypotheses", [])
    if hypotheses:
        _section("Attack Hypotheses")
        for h in hypotheses:
            tactics = ", ".join(h.get("mitre_tactics", []))
            console.print(
                f"  [bold]{h.get('category', '?')}[/bold] ({tactics}): "
                f"{h.get('description', '')}"
            )

    # Verdict
    if verdict:
        _section("Verdict")
        disp = verdict.get("disposition", "undetermined")
        disp_colour = {
            "true_positive": "bold red",
            "likely_true_positive": "red",
            "benign_positive": "yellow",
            "false_positive": "green",
            "undetermined": "dim",
        }.get(disp, "white")
        console.print(f"  Disposition: [{disp_colour}]{disp.replace('_', ' ').upper()}[/]")
        console.print(f"  Severity:    {verdict.get('severity', '?').upper()}")
        console.print(f"  Confidence:  {verdict.get('confidence', 0):.0%}")
        console.print(f"\n  {verdict.get('summary', '')}")

        actions: list[str] = verdict.get("recommended_actions", [])
        if actions:
            console.print("\n[bold]Recommended Actions:[/bold]")
            for i, action in enumerate(actions, 1):
                console.print(f"  {i}. {action}")

    # Investigation steps
    steps: list[str] = triage.get("investigation_steps", [])
    if steps:
        _section("Investigation Steps")
        for step in steps:
            console.print(f"  • {step}")

    # Errors
    if report_dict.get("errors"):
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for err in report_dict["errors"]:
            console.print(f"  [yellow]⚠[/yellow] {err}")

    # LLM analysis
    if report_dict.get("llm_analysis"):
        _section("LLM Analysis")
        console.print(Markdown(report_dict["llm_analysis"]))


# ── resolve-entity ─────────────────────────────────────────────────────────────

async def _resolve_entity(identifier: str, output_format: str) -> None:
    from threatlens.entities.entity_resolver import EntityResolver

    resolver = EntityResolver()
    with console.status(f"[bold green]Resolving {identifier}…"):
        result = await resolver.resolve(identifier)

    data = result.model_dump(mode="json")

    if output_format == "json":
        click.echo(json.dumps(data, indent=2, default=str))
        return

    risk_label = result.risk_label or "Unknown"
    risk_colours = {
        "Critical": "bold red",
        "High": "bold red",
        "Medium": "yellow",
        "Low": "cyan",
        "Clean": "green",
    }
    colour = risk_colours.get(risk_label, "white")

    console.print(Panel(
        f"[bold]{result.identifier}[/bold]  |  Kind: {result.kind.value}  |  "
        f"Risk: [{colour}]{risk_label}[/] ({result.risk_score:.1f}/10)",
        title="Entity Resolution",
    ))

    if result.risk_indicators:
        console.print("\n[bold]Risk Indicators:[/bold]")
        for ind in result.risk_indicators:
            console.print(f"  • {ind}")

    if result.threat_intel_hits:
        console.print("\n[bold]Threat Intelligence:[/bold]")
        t = Table("Provider", "Status", "Score", "Categories", box=box.SIMPLE)
        for hit in result.threat_intel_hits:
            status = (
                "[red]MALICIOUS[/red]" if hit.malicious
                else "[yellow]Suspicious[/yellow]" if hit.suspicious
                else "[green]Clean[/green]"
            )
            t.add_row(
                hit.provider,
                status,
                f"{hit.score:.1f}",
                ", ".join(hit.categories),
            )
        console.print(t)

    if result.azure_resource_details:
        console.print("\n[bold]Azure Resource Details:[/bold]")
        for k, v in result.azure_resource_details.items():
            if v:
                console.print(f"  {k}: {v}")


# ── investigate-identity ───────────────────────────────────────────────────────

async def _investigate_identity(
    identifier: str, lookback_days: int, output_format: str
) -> None:
    from threatlens.analysis.identity_abuse import IdentityAbuseAnalyser

    analyser = IdentityAbuseAnalyser()
    with console.status(f"[bold green]Investigating identity {identifier}…"):
        result = await analyser.investigate(identifier, lookback_days=lookback_days)

    data = result.model_dump(mode="json")

    if output_format == "json":
        click.echo(json.dumps(data, indent=2, default=str))
        return

    risk_colours = {"Critical": "bold red", "High": "bold red", "Medium": "yellow", "Low": "cyan"}
    rl = data.get("risk_level", "Unknown")
    rs = data.get("risk_score", 0)
    colour = risk_colours.get(rl, "white")

    _section(f"Identity Investigation: {identifier}")
    console.print(f"Risk: [{colour}]{rl.upper()}[/]  ({rs:.1f}/10)")

    profile = data.get("profile", {})
    if profile:
        console.print(f"\nDisplay Name: {profile.get('display_name', '?')}")
        console.print(f"UPN:          {profile.get('upn', '?')}")
        console.print(f"MFA:          {'✓ Enabled' if profile.get('mfa_enabled') else '✗ Not registered'}")
        roles = profile.get("roles", [])
        if roles:
            console.print(f"Roles:        {', '.join(r.get('role_name', '?') for r in roles[:5])}")

    findings: list[str] = data.get("findings", [])
    if findings:
        console.print("\n[bold]Findings:[/bold]")
        for f in findings:
            console.print(f"  • {f}")

    actions: list[str] = data.get("recommended_actions", [])
    if actions:
        console.print("\n[bold]Recommended Actions:[/bold]")
        for i, action in enumerate(actions, 1):
            console.print(f"  {i}. {action}")

    sign_ins = data.get("sign_in_summary", {})
    if sign_ins:
        console.print("\n[bold]Sign-in Summary:[/bold]")
        for k, v in sign_ins.items():
            console.print(f"  {k}: {v}")


# ── investigate-resource ───────────────────────────────────────────────────────

async def _investigate_resource(
    resource_id: str, lookback_hours: int, output_format: str
) -> None:
    from threatlens.analysis.resource_access_analysis import ResourceAccessAnalyser

    analyser = ResourceAccessAnalyser()
    with console.status(f"[bold green]Investigating resource {resource_id[:60]}…"):
        result = await analyser.analyse_resource(resource_id, lookback_hours=lookback_hours)

    if output_format == "json":
        click.echo(json.dumps(result, indent=2, default=str))
        return

    risk_score = result.get("risk_score", 0)
    colour = "bold red" if risk_score >= 7 else "yellow" if risk_score >= 4 else "green"

    _section("Resource Access Investigation")
    console.print(Panel(
        f"[bold]{resource_id}[/bold]\n"
        f"Type: {result.get('resource_type', 'unknown')}\n"
        f"Risk Score: [{colour}]{risk_score:.1f}/10[/]",
        title="Resource Summary",
    ))

    metrics = {
        "Total Events": result.get("total_events", 0),
        "Sensitive Operations": result.get("sensitive_operations", 0),
        "Distinct Callers": result.get("distinct_callers", 0),
        "Failed Operations": result.get("failed_operations", 0),
    }
    t = Table(box=box.SIMPLE)
    t.add_column("Metric")
    t.add_column("Count", justify="right")
    for k, v in metrics.items():
        t.add_row(k, str(v))
    console.print(t)

    findings: list[str] = result.get("findings", [])
    if findings:
        console.print("\n[bold]Findings:[/bold]")
        for f in findings:
            console.print(f"  • {f}")
    else:
        console.print("\n[green]No significant findings detected.[/green]")


# ── breachmanager ──────────────────────────────────────────────────────────────

async def _breachmanager(
    scenario: str,
    incident_json: str | None,
    mode: str,
    auth_strategy: str,
    tenant_ids: tuple[str, ...],
    lighthouse: bool,
    output_format: str,
) -> None:
    from threatlens.core.breach_manager_engine import BreachManagerEngine, BreachManagerInput

    incident: dict[str, Any] | None = json.loads(incident_json) if incident_json else None

    engine = BreachManagerEngine()
    with console.status("[bold green]Generating Breach Manager plan…"):
        plan = await engine.plan(
            BreachManagerInput(
                scenario=scenario,
                incident=incident,
                mode=mode,
                auth_strategy=auth_strategy,
                tenant_ids=list(tenant_ids),
                lighthouse=lighthouse,
            )
        )

    data = plan.model_dump(mode="json")
    if output_format == "json":
        click.echo(json.dumps(data, indent=2, default=str))
        return

    _section("Breach Manager Plan")
    console.print(Panel(scenario, title="Scenario"))
    console.print(f"Mode: [bold]{plan.input_mode.upper()}[/bold]")
    console.print(f"Auth Strategy: [bold]{plan.auth_strategy}[/bold]")
    console.print(f"Execution Policy: [bold yellow]{plan.execution_policy}[/bold yellow]")
    console.print("[dim]Breach Manager proposes commands only; it never executes remediation commands automatically.[/dim]")

    if plan.tenant_targets:
        console.print("\n[bold]Tenant Targets:[/bold]")
        for t in plan.tenant_targets:
            suffix = " (Lighthouse)" if t.lighthouse_delegated else ""
            console.print(f"  • {t.tenant_id} / {t.subscription_id or 'n/a'}{suffix}")

    if plan.selected_playbooks:
        console.print("\n[bold]Activated Playbooks:[/bold]")
        for skill in plan.selected_playbooks:
            console.print(f"  • {skill}")

    if plan.skills:
        console.print("\n[bold]Skills in Use:[/bold]")
        for skill in plan.skills:
            console.print(f"  • {skill.name} ({skill.category})")

    if plan.tools:
        console.print("\n[bold]Tools in Use:[/bold]")
        for tool in plan.tools:
            gated = " (human approval)" if tool.requires_human_approval else ""
            console.print(f"  • {tool.name}{gated}")

    if plan.attack_path_hypotheses:
        console.print("\n[bold]Attack Hypotheses:[/bold]")
        for hypothesis in plan.attack_path_hypotheses:
            console.print(f"  • {hypothesis}")

    if plan.triage_checkpoints:
        console.print("\n[bold]Analyst Triage Questions:[/bold]")
        for question in plan.triage_checkpoints:
            console.print(f"  • {question}")

    if plan.actions:
        console.print("\n[bold cyan]Execution Plan[/bold cyan]")
        for idx, action in enumerate(plan.actions, 1):
            console.print(f"  {idx}. [bold]{action.phase.upper()}[/bold] — {action.objective}")
            console.print(f"     ↳ {action.details}")
            if action.requires_approval:
                console.print("     [yellow]Analyst approval required[/yellow]")
            if action.command_proposals:
                console.print("     [bold]Command Proposals (ask before execution):[/bold]")
                for proposal in action.command_proposals:
                    console.print(f"       - {proposal.title} [{proposal.risk}]")
                    console.print(f"         {proposal.command}")
            if action.guidance:
                refs = "; ".join(f"{r.framework}: {r.title}" for r in action.guidance)
                console.print(f"     [dim]Refs:[/dim] {refs}")

    if plan.future_api_integrations:
        console.print("\n[bold]Future API Integrations:[/bold]")
        for api in plan.future_api_integrations:
            console.print(
                f"  • {api.name} | endpoint var: {api.endpoint_env_var} | token var: {api.token_env_var}"
            )
