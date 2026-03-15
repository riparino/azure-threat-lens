"""Rich terminal output helpers for Azure Threat Lens CLI."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(stderr=False)
err_console = Console(stderr=True)

# Severity → colour mapping
_SEVERITY_COLOURS: dict[str, str] = {
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Informational": "dim",
    "Critical": "bold red",
    "Unknown": "white",
}

_RISK_COLOURS: dict[str, str] = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Clean": "green",
    "Unknown": "dim",
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "none": "green",
}


def severity_badge(severity: str) -> Text:
    colour = _SEVERITY_COLOURS.get(severity, "white")
    return Text(f" {severity} ", style=f"bold {colour} on default")


def risk_badge(label: str) -> Text:
    colour = _RISK_COLOURS.get(label, "white")
    return Text(f" {label.upper()} ", style=f"bold {colour}")


def print_header(title: str, subtitle: str = "") -> None:
    text = Text(title, style="bold blue")
    if subtitle:
        text.append(f"\n{subtitle}", style="dim")
    console.print(Panel(text, box=box.DOUBLE_EDGE, border_style="blue"))


def print_triage_result(result: Any, output_format: str = "rich") -> None:
    if output_format == "json":
        console.print_json(result.model_dump_json(indent=2))
        return

    # Header panel
    score_colour = "red" if result.priority_score >= 7 else "yellow" if result.priority_score >= 4 else "green"
    header = Text()
    header.append(f"#{result.incident_number} – ", style="dim")
    header.append(result.title, style="bold white")
    header.append(f"\n\nPriority Score: ", style="dim")
    header.append(f"{result.priority_score:.1f}/10", style=f"bold {score_colour}")
    header.append(f"  |  Label: ")
    header.append_text(risk_badge(result.priority_label))
    header.append(f"  |  Severity: ")
    header.append_text(severity_badge(result.severity.value))
    console.print(Panel(header, title="[bold blue]Incident Triage Result[/bold blue]", box=box.ROUNDED))

    # Summary
    console.print(Panel(result.summary, title="Summary", border_style="dim"))

    # Key indicators
    if result.key_indicators:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("", style="yellow", no_wrap=True)
        table.add_column("")
        for i, indicator in enumerate(result.key_indicators, 1):
            table.add_row(f"[{i}]", indicator)
        console.print(Panel(table, title="Key Indicators", border_style="yellow"))

    # Recommended actions
    if result.recommended_actions:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("", style="green", no_wrap=True)
        table.add_column("")
        for i, action in enumerate(result.recommended_actions, 1):
            table.add_row(f"→", action)
        console.print(Panel(table, title="Recommended Actions", border_style="green"))

    # MITRE
    if result.mitre_tactics or result.mitre_techniques:
        tactics_text = "  ".join(f"[yellow]{t}[/yellow]" for t in result.mitre_tactics) or "[dim]none[/dim]"
        tech_text = "  ".join(f"[cyan]{t}[/cyan]" for t in result.mitre_techniques) or "[dim]none[/dim]"
        console.print(
            Panel(
                f"Tactics:    {tactics_text}\nTechniques: {tech_text}",
                title="MITRE ATT&CK",
                border_style="dim",
            )
        )

    # LLM analysis
    if result.llm_analysis and result.llm_analysis.strip():
        console.print(Panel(Markdown(result.llm_analysis), title="[bold magenta]AI Analysis[/bold magenta]", border_style="magenta"))


def print_entity_result(result: Any, output_format: str = "rich") -> None:
    if output_format == "json":
        console.print_json(result.model_dump_json(indent=2))
        return

    header = Text()
    header.append(f"{result.entity_kind.value}: ", style="dim")
    header.append(result.identifier, style="bold white")
    header.append(f"\n\nRisk: ")
    header.append_text(risk_badge(result.risk_label))
    header.append(f"  Score: ")
    score_colour = "red" if result.risk_score >= 7 else "yellow" if result.risk_score >= 4 else "green"
    header.append(f"{result.risk_score:.1f}/10", style=f"bold {score_colour}")
    console.print(Panel(header, title="[bold blue]Entity Resolution Result[/bold blue]", box=box.ROUNDED))

    # Context
    if result.context:
        ctx_lines = "\n".join(f"  {k}: {v}" for k, v in result.context.items() if not isinstance(v, (dict, list)))
        if ctx_lines:
            console.print(Panel(ctx_lines, title="Context", border_style="dim"))

    # Threat intel
    if result.threat_intel_hits:
        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("Provider", style="bold")
        table.add_column("Malicious")
        table.add_column("Suspicious")
        table.add_column("Score")
        table.add_column("Categories")
        for hit in result.threat_intel_hits:
            table.add_row(
                hit.provider,
                "[red]YES[/red]" if hit.malicious else "[green]No[/green]",
                "[yellow]YES[/yellow]" if hit.suspicious else "[green]No[/green]",
                f"{hit.score:.1f}" if hit.score is not None else "—",
                ", ".join(hit.categories[:3]) or "—",
            )
        console.print(Panel(table, title="Threat Intelligence", border_style="yellow"))

    if result.llm_analysis and result.llm_analysis.strip():
        console.print(Panel(Markdown(result.llm_analysis), title="[bold magenta]AI Analysis[/bold magenta]", border_style="magenta"))


def print_identity_result(result: Any, output_format: str = "rich") -> None:
    if output_format == "json":
        console.print_json(result.model_dump_json(indent=2))
        return

    header = Text()
    header.append(result.display_name or result.user_principal_name, style="bold white")
    header.append(f"\n{result.user_principal_name}", style="dim")
    header.append(f"\n\nRisk: ")
    header.append_text(risk_badge(result.risk_level))
    header.append(f"  Score: ")
    score_colour = "red" if result.risk_score >= 7 else "yellow" if result.risk_score >= 4 else "green"
    header.append(f"{result.risk_score:.1f}/10", style=f"bold {score_colour}")
    console.print(Panel(header, title="[bold blue]Identity Investigation Result[/bold blue]", box=box.ROUNDED))

    # Profile overview
    if result.profile:
        p = result.profile
        profile_text = (
            f"  Job Title:    {p.job_title or '—'}\n"
            f"  Department:   {p.department or '—'}\n"
            f"  Account:      {'[green]Enabled[/green]' if p.account_enabled else '[red]DISABLED[/red]'}\n"
            f"  On-prem sync: {'Yes' if p.on_premises_sync_enabled else 'No'}\n"
        )
        console.print(Panel(profile_text, title="User Profile", border_style="dim"))

    # Sign-in stats
    stats_text = (
        f"  Sign-ins analysed:    {len(result.sign_in_events)}\n"
        f"  High-risk sign-ins:   [{'red' if result.high_risk_sign_ins else 'green'}]{result.high_risk_sign_ins}[/]\n"
        f"  Impossible travel:    [{'red bold' if result.impossible_travel_detected else 'green'}]{'YES' if result.impossible_travel_detected else 'No'}[/]\n"
        f"  Legacy auth sign-ins: [{'yellow' if result.legacy_auth_sign_ins else 'green'}]{result.legacy_auth_sign_ins}[/]\n"
        f"  MFA registered:       [{'green' if result.mfa_status and result.mfa_status.is_mfa_registered else 'red bold'}]{'Yes' if result.mfa_status and result.mfa_status.is_mfa_registered else 'NO'}[/]\n"
    )
    console.print(Panel(stats_text, title="Sign-in Analysis", border_style="cyan"))

    # Key findings
    if result.key_findings:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("", style="bold red", no_wrap=True)
        table.add_column("")
        for finding in result.key_findings:
            icon = "⚠" if "CRITICAL" in finding or "HIGH" in finding else "•"
            table.add_row(icon, finding)
        console.print(Panel(table, title="Key Findings", border_style="red"))

    # Privileged roles
    if result.privileged_roles:
        roles_text = "\n".join(f"  • [yellow]{r}[/yellow]" for r in result.privileged_roles)
        console.print(Panel(roles_text, title="Privileged Roles", border_style="yellow"))

    # Recommended actions
    if result.recommended_actions:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("", style="green", no_wrap=True)
        table.add_column("")
        for action in result.recommended_actions:
            table.add_row("→", action)
        console.print(Panel(table, title="Recommended Actions", border_style="green"))

    if result.llm_analysis and result.llm_analysis.strip():
        console.print(Panel(Markdown(result.llm_analysis), title="[bold magenta]AI Analysis[/bold magenta]", border_style="magenta"))


def print_incident_list(results: list[Any], output_format: str = "rich") -> None:
    if output_format == "json":
        data = [r.model_dump() for r in results]
        console.print_json(json.dumps(data, indent=2, default=str))
        return

    table = Table(
        box=box.ROUNDED,
        title="[bold blue]Incident Triage Summary[/bold blue]",
        show_header=True,
        header_style="bold",
    )
    table.add_column("#", style="dim", width=6)
    table.add_column("Title", max_width=50)
    table.add_column("Severity", justify="center", width=14)
    table.add_column("Priority", justify="center", width=10)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Tactics", max_width=30)

    for r in results:
        score_colour = "red" if r.priority_score >= 7 else "yellow" if r.priority_score >= 4 else "green"
        sev_colour = _SEVERITY_COLOURS.get(r.severity.value, "white")
        table.add_row(
            str(r.incident_number),
            r.title[:48] + ("…" if len(r.title) > 48 else ""),
            f"[{sev_colour}]{r.severity.value}[/{sev_colour}]",
            f"[{score_colour}]{r.priority_label}[/{score_colour}]",
            f"[{score_colour}]{r.priority_score:.1f}[/{score_colour}]",
            ", ".join(r.mitre_tactics[:2]) or "—",
        )
    console.print(table)
