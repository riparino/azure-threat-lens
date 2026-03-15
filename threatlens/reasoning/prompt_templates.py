"""Prompt templates for Azure OpenAI-based investigation analysis."""

from __future__ import annotations

import json
from typing import Any

_SYSTEM_SOC_ANALYST = (
    "You are a senior SOC analyst and Azure security expert. "
    "Analyse the provided investigation data and return a concise, actionable assessment. "
    "Focus on: confirmed malicious indicators, attacker objectives, and specific remediation steps. "
    "Do not speculate beyond the evidence provided. Be direct and factual."
)

_SYSTEM_THREAT_HUNTER = (
    "You are a threat hunter specialising in Azure and Microsoft 365 environments. "
    "Identify MITRE ATT&CK techniques, lateral movement paths, and persistence mechanisms "
    "from the provided investigation data. Suggest specific KQL queries to validate hypotheses."
)


def build_investigation_prompt(report: dict[str, Any]) -> str:
    """Build a full investigation analysis prompt from a completed InvestigationReport."""
    incident_id = report.get("incident_id", "unknown")
    triage = report.get("triage", {})
    verdict = report.get("verdict", {})

    sections: list[str] = [
        f"## Incident Investigation: {incident_id}",
        "",
        "### Triage Summary",
        f"- Risk level: {triage.get('risk_level', 'unknown')}",
        f"- Summary: {triage.get('summary', 'N/A')}",
        f"- Confidence: {triage.get('confidence', 0):.0%}",
    ]

    # Key entities
    key_entities: list[dict[str, Any]] = triage.get("key_entities", [])
    if key_entities:
        sections.append("\n### Key Entities Identified")
        for e in key_entities[:10]:
            risk = ", ".join(e.get("risk_indicators", []))
            sections.append(
                f"- [{e.get('kind', '?')}] {e.get('identifier', '?')}"
                + (f" — {risk}" if risk else "")
            )

    # Attack hypotheses
    hypotheses: list[dict[str, Any]] = triage.get("attack_hypotheses", [])
    if hypotheses:
        sections.append("\n### Attack Hypotheses")
        for h in hypotheses:
            tactics = ", ".join(h.get("mitre_tactics", []))
            sections.append(f"- **{h.get('category', '?')}** ({tactics}): {h.get('description', '')}")

    # Identity findings
    identity: list[dict[str, Any]] = report.get("identity_analysis", [])
    if identity:
        sections.append("\n### Identity Analysis Findings")
        for inv in identity:
            for finding in inv.get("findings", [])[:5]:
                sections.append(f"- {finding}")

    # Privilege escalation
    priv: dict[str, Any] = report.get("privilege_analysis", {})
    if priv.get("findings"):
        sections.append("\n### Privilege Escalation Findings")
        for finding in priv.get("findings", []):
            sections.append(f"- {finding}")

    # Token abuse
    token: dict[str, Any] = report.get("token_analysis", {})
    if token.get("suspicious_consents"):
        sections.append("\n### Suspicious OAuth Consents")
        for consent in token.get("suspicious_consents", [])[:5]:
            sections.append(f"- {consent}")

    # Defender alerts
    defender: list[dict[str, Any]] = report.get("defender_alerts", [])
    if defender:
        sections.append("\n### Defender XDR Alerts")
        for alert in defender[:5]:
            title = alert.get("Title") or alert.get("title", "?")
            sev = alert.get("Severity") or alert.get("severity", "?")
            techniques = alert.get("AttackTechniques") or alert.get("mitreTechniques", [])
            sections.append(f"- [{sev}] {title}" + (f" — {techniques}" if techniques else ""))

    # Preliminary verdict
    if verdict:
        sections.append("\n### Preliminary Verdict")
        sections.append(f"- Disposition: **{verdict.get('disposition', '?')}**")
        sections.append(f"- Severity: {verdict.get('severity', '?')}")
        sections.append(f"- Confidence: {verdict.get('confidence', 0):.0%}")
        sections.append(f"- Summary: {verdict.get('summary', '')}")

    sections.append(
        "\n---\n"
        "Based on the above investigation data, provide:\n"
        "1. A brief assessment of whether this is a true positive or false positive, and why.\n"
        "2. The most likely attacker objective and technique (MITRE ATT&CK reference if applicable).\n"
        "3. Any additional evidence or queries you would recommend to confirm the verdict.\n"
        "4. Top 3 immediate remediation actions in priority order."
    )

    return "\n".join(sections)


def build_entity_analysis_prompt(entity: dict[str, Any]) -> str:
    """Build a focused prompt for analysing a single resolved entity."""
    kind = entity.get("kind", "entity")
    identifier = entity.get("identifier", "unknown")
    risk_score = entity.get("risk_score", 0)
    risk_indicators = entity.get("risk_indicators", [])
    ti_hits = entity.get("threat_intel_hits", [])

    lines: list[str] = [
        f"## Entity Analysis: {identifier} ({kind})",
        f"Risk Score: {risk_score}/10",
        "",
    ]
    if risk_indicators:
        lines.append("Risk Indicators:")
        for ind in risk_indicators:
            lines.append(f"  - {ind}")

    if ti_hits:
        lines.append("\nThreat Intelligence:")
        for hit in ti_hits:
            status = "MALICIOUS" if hit.get("malicious") else "suspicious" if hit.get("suspicious") else "clean"
            lines.append(
                f"  - [{hit.get('provider')}] {status}: score={hit.get('score', 0):.1f}, "
                f"categories={hit.get('categories', [])}"
            )

    azure_details = entity.get("azure_resource_details", {})
    if azure_details:
        lines.append(f"\nAzure Resource: type={azure_details.get('type', '?')}, "
                     f"location={azure_details.get('location', '?')}, "
                     f"rg={azure_details.get('resourceGroup', '?')}")

    lines.append(
        "\nProvide: (1) a one-sentence assessment of whether this entity is a threat actor or "
        "a victim/compromised asset; (2) recommended investigation steps specific to this entity type."
    )
    return "\n".join(lines)


def build_kql_generation_prompt(
    hypothesis: str,
    entity_type: str,
    identifier: str,
    available_tables: list[str] | None = None,
) -> str:
    """Generate a KQL query for a specific hypothesis and entity."""
    tables_hint = (
        f"Available tables: {', '.join(available_tables)}"
        if available_tables
        else "Common tables: SigninLogs, AuditLogs, AzureActivity, SecurityAlert, DeviceEvents, OfficeActivity"
    )
    return (
        f"Generate a KQL query for Microsoft Sentinel to investigate the following hypothesis:\n\n"
        f"Hypothesis: {hypothesis}\n"
        f"Entity type: {entity_type}\n"
        f"Entity identifier: {identifier}\n"
        f"{tables_hint}\n\n"
        "Requirements:\n"
        "- Use a lookback of 72 hours (ago(72h))\n"
        "- Project only the most relevant columns\n"
        "- Add a brief comment explaining what the query detects\n"
        "- Return only the KQL query, no explanation outside the code"
    )


def build_summary_prompt(report_json: str) -> str:
    """Build a prompt for a concise executive summary of a completed investigation."""
    return (
        "Write a concise executive summary (3-5 sentences) of the following Azure security "
        "investigation for a CISO-level audience. Focus on: what happened, what was at risk, "
        f"and what actions are recommended.\n\nInvestigation data:\n{report_json}"
    )
