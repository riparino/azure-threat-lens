"""Triage Engine – structured incident analysis with optional LLM reasoning.

This module provides a self-contained triage engine that accepts raw incident,
alert, and entity data and produces a structured JSON-serialisable output.

It operates in two modes:
- **Deterministic** (default): Pure rule-based analysis, no external calls.
- **LLM-assisted**: Calls Claude for natural-language reasoning; requires
  ``ATL_ANTHROPIC_API_KEY`` to be configured.

Usage::

    from azure_threat_lens.analysis.triage_engine import TriageEngine, TriageEngineInput

    engine = TriageEngine()
    result = await engine.run(
        TriageEngineInput(
            incident=incident_dict,
            alerts=alerts_list,
            entities=entities_list,
            time_range={"start": "...", "end": "..."},
        )
    )
    print(result.model_dump_json(indent=2))
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from azure_threat_lens.logging import get_logger

log = get_logger(__name__)

# ── MITRE ATT&CK tactic → technique pattern heuristics ───────────────────────
_TACTIC_PATTERNS: dict[str, list[str]] = {
    "InitialAccess": ["anonymous ip", "impossible travel", "unfamiliar sign-in", "spray", "brute-force", "phish"],
    "Execution": ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bash", "python script"],
    "Persistence": ["scheduled task", "registry run", "startup", "service install", "autorun", "cron"],
    "PrivilegeEscalation": ["uac bypass", "token impersonation", "sudo", "setuid", "privilege", "admin"],
    "DefenseEvasion": ["obfuscat", "encode", "base64", "disable antivirus", "tamper", "stealth", "clear log"],
    "CredentialAccess": ["credential", "password", "lsass", "mimikatz", "kerberoast", "dcsync", "ntlm", "hash"],
    "Discovery": ["net user", "whoami", "ipconfig", "arp", "nmap", "scan", "enum", "ldap query"],
    "LateralMovement": ["psexec", "wmi", "smb", "remote desktop", "rdp", "winrm", "ssh", "pass-the-hash"],
    "Collection": ["archive", "compress", "zip", "exfil", "staged", "clipboard", "keylog", "screenshot"],
    "Exfiltration": ["upload", "ftp", "dns tunnel", "http post", "megaupload", "pastebin", "exfiltrat"],
    "Impact": ["ransomware", "encrypt", "wipe", "delete", "shutdown", "ddos", "deface"],
    "CommandAndControl": ["c2", "beacon", "cobalt strike", "metasploit", "dns beacon", "reverse shell"],
}

# Known KQL query templates for common attack patterns
_KQL_TEMPLATES: dict[str, str] = {
    "signin_anomaly": """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "{upn}"
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn
| order by TimeGenerated desc""",
    "impossible_travel": """SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "{upn}"
| project TimeGenerated, IPAddress, Location
| order by TimeGenerated asc
| extend prev_time = prev(TimeGenerated), prev_country = prev(Location.countryOrRegion)
| where Location.countryOrRegion != prev_country
| extend time_diff_hours = datetime_diff('hour', TimeGenerated, prev_time)
| where time_diff_hours < 4""",
    "ip_activity": """CommonSecurityLog
| where TimeGenerated > ago({hours}h)
| where SourceIP == "{ip}" or DestinationIP == "{ip}"
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction, Activity
| order by TimeGenerated desc
| take 100""",
    "host_process": """DeviceProcessEvents
| where TimeGenerated > ago({hours}h)
| where DeviceName contains "{hostname}"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, ParentProcessName
| order by TimeGenerated desc
| take 100""",
    "defender_alerts_user": """AlertEvidence
| where TimeGenerated > ago(30d)
| where AccountUpn =~ "{upn}"
| join kind=inner AlertInfo on AlertId
| project TimeGenerated, Title, Severity, Category, AccountUpn, AttackTechniques
| order by TimeGenerated desc""",
    "sentinel_related_incidents": """SecurityIncident
| where TimeGenerated > ago({hours}h)
| where Entities contains "{identifier}"
| project TimeGenerated, Title, Severity, Status, IncidentNumber
| order by TimeGenerated desc""",
    "oauth_app_consents": """AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Consent to application"
| where InitiatedBy.user.userPrincipalName =~ "{upn}"
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated desc""",
}


# ── Data models ────────────────────────────────────────────────────────────────

class TriageEngineInput(BaseModel):
    """Input schema for the TriageEngine."""

    incident: dict[str, Any] = Field(..., description="Raw incident JSON from Sentinel API or ATL models")
    alerts: list[dict[str, Any]] = Field(default_factory=list, description="Alerts attached to the incident")
    entities: list[dict[str, Any]] = Field(default_factory=list, description="Entities extracted from alerts")
    time_range: dict[str, str] = Field(
        default_factory=dict,
        description="Analysis time window: {start: ISO8601, end: ISO8601}",
    )


class EngineEntity(BaseModel):
    """A structured entity extracted by the engine."""

    kind: str
    identifier: str
    friendly_name: str = ""
    risk_indicators: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class SuggestedQuery(BaseModel):
    """A KQL query suggestion with context."""

    name: str
    description: str
    kql: str
    target_table: str = ""


class TriageEngineOutput(BaseModel):
    """Structured output of the TriageEngine – always JSON-serialisable."""

    summary: str
    risk_level: str  # critical | high | medium | low | informational
    entities: list[EngineEntity]
    attack_patterns: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    recommended_queries: list[SuggestedQuery]
    investigation_steps: list[str]
    confidence: str  # high | medium | low
    llm_reasoning: str = ""
    engine_mode: str = "deterministic"  # deterministic | llm_assisted
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Engine ─────────────────────────────────────────────────────────────────────

class TriageEngine:
    """Analyses a Sentinel incident and produces structured triage output.

    The engine can run in two modes:
    - ``use_llm=False`` (default): Fully deterministic, no API calls.
    - ``use_llm=True``: Enriches with LLM reasoning via Claude.
    """

    def __init__(self, use_llm: bool = False) -> None:
        self._use_llm = use_llm
        self._llm: Any = None
        if use_llm:
            try:
                from azure_threat_lens.llm.reasoning import LLMReasoner
                self._llm = LLMReasoner()
                if not self._llm.is_available:
                    log.warning("triage_engine.llm_not_configured", fallback="deterministic")
                    self._use_llm = False
            except ImportError:
                log.warning("triage_engine.llm_import_failed", fallback="deterministic")
                self._use_llm = False

    async def run(self, data: TriageEngineInput) -> TriageEngineOutput:
        """Execute the triage engine and return structured output."""
        log.info(
            "triage_engine.run",
            incident_id=data.incident.get("incidentId", data.incident.get("incident_id", "?")),
            mode="llm_assisted" if self._use_llm else "deterministic",
        )

        entities = self._extract_entities(data.entities)
        attack_patterns = self._identify_attack_patterns(data.incident, data.alerts, data.entities)
        tactics, techniques = self._extract_mitre(data.incident, data.alerts)
        risk_level = self._assess_risk(data.incident, data.alerts, attack_patterns)
        summary = self._build_summary(data.incident, data.alerts, entities, risk_level)
        queries = self._generate_queries(data.incident, data.alerts, entities, data.time_range)
        steps = self._investigation_steps(data.incident, data.alerts, entities, attack_patterns)
        confidence = self._assess_confidence(data.incident, data.alerts, data.entities)

        output = TriageEngineOutput(
            summary=summary,
            risk_level=risk_level,
            entities=entities,
            attack_patterns=attack_patterns,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            recommended_queries=queries,
            investigation_steps=steps,
            confidence=confidence,
            engine_mode="deterministic",
        )

        if self._use_llm and self._llm:
            output.llm_reasoning = await self._llm.analyse_triage(data.model_dump())
            output.engine_mode = "llm_assisted"

        return output

    # ── Entity extraction ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_entities(raw_entities: list[dict[str, Any]]) -> list[EngineEntity]:
        """Parse raw entity dicts into typed EngineEntity objects."""
        result: list[EngineEntity] = []
        for raw in raw_entities:
            kind = raw.get("entityType", raw.get("kind", raw.get("entity_type", "Unknown")))
            props = raw.get("properties", raw)
            identifier = (
                props.get("address")
                or props.get("hostName")
                or props.get("userPrincipalName")
                or props.get("accountName")
                or props.get("url")
                or props.get("hashValue")
                or props.get("identifier", "")
                or raw.get("identifier", "")
            )
            friendly_name = props.get("friendlyName", raw.get("friendly_name", identifier))
            result.append(
                EngineEntity(
                    kind=kind,
                    identifier=str(identifier),
                    friendly_name=str(friendly_name),
                    raw=raw,
                )
            )
        return result

    # ── Attack pattern detection ───────────────────────────────────────────────

    @staticmethod
    def _identify_attack_patterns(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[dict[str, Any]],
    ) -> list[str]:
        """Identify likely attack patterns from text signals."""
        patterns: list[str] = []

        # Collect all text to search
        corpus = " ".join([
            incident.get("title", ""),
            incident.get("description", ""),
            *[a.get("alertDisplayName", a.get("title", "")) for a in alerts],
            *[a.get("description", "") for a in alerts],
        ]).lower()

        for tactic, keywords in _TACTIC_PATTERNS.items():
            if any(kw in corpus for kw in keywords):
                patterns.append(tactic)

        # Entity-type based patterns
        entity_kinds = {e.get("entityType", e.get("kind", "")) for e in entities}
        if "Account" in entity_kinds and "Ip" in entity_kinds:
            patterns.append("AccountCompromiseWithExternalIP")
        if "Host" in entity_kinds and len(entity_kinds) > 2:
            patterns.append("LateralMovementIndicators")

        return list(dict.fromkeys(patterns))  # deduplicate, preserve order

    # ── MITRE extraction ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_mitre(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]]:
        tactics: list[str] = list(incident.get("tactics", []))
        techniques: list[str] = list(incident.get("techniques", []))
        for alert in alerts:
            for tactic in alert.get("tactics", []):
                if tactic not in tactics:
                    tactics.append(tactic)
            for tech in alert.get("techniques", alert.get("mitreTechniques", [])):
                if tech not in techniques:
                    techniques.append(tech)
        return tactics, techniques

    # ── Risk assessment ────────────────────────────────────────────────────────

    @staticmethod
    def _assess_risk(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        attack_patterns: list[str],
    ) -> str:
        severity = incident.get("severity", "Informational")
        severity_rank = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1}
        rank = severity_rank.get(severity, 1)

        # Bump for high-signal patterns
        high_signal = {"CredentialAccess", "Exfiltration", "Impact", "CommandAndControl"}
        if any(p in high_signal for p in attack_patterns):
            rank = min(rank + 1, 4)

        # Bump for multiple alerts
        if len(alerts) >= 5:
            rank = min(rank + 1, 4)

        return {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(rank, "low")

    # ── Summary ────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_summary(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[EngineEntity],
        risk_level: str,
    ) -> str:
        title = incident.get("title", "Unknown Incident")
        inc_num = incident.get("incidentNumber", incident.get("incident_number", "?"))
        severity = incident.get("severity", "Unknown")
        entity_summary = ", ".join(
            f"{e.kind}:{e.identifier}" for e in entities[:5]
        ) or "none identified"
        alert_count = len(alerts)
        return (
            f"Incident #{inc_num} – '{title}' ({severity} severity, {risk_level.upper()} risk). "
            f"{alert_count} correlated alert(s) with entities: {entity_summary}."
        )

    # ── KQL query generation ───────────────────────────────────────────────────

    def _generate_queries(
        self,
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[EngineEntity],
        time_range: dict[str, str],
    ) -> list[SuggestedQuery]:
        queries: list[SuggestedQuery] = []
        hours = self._time_range_hours(time_range, default=168)

        # Extract identifiers by type
        accounts = [e for e in entities if e.kind in ("Account", "account")]
        ips = [e for e in entities if e.kind in ("Ip", "ip", "IP")]
        hosts = [e for e in entities if e.kind in ("Host", "host")]

        for account in accounts[:3]:
            upn = account.identifier
            queries.append(SuggestedQuery(
                name=f"sign_in_anomalies_{account.friendly_name or upn}",
                description=f"Risky sign-in events for {upn} in the last 7 days",
                kql=_KQL_TEMPLATES["signin_anomaly"].format(upn=upn),
                target_table="SigninLogs",
            ))
            queries.append(SuggestedQuery(
                name=f"defender_alerts_{account.friendly_name or upn}",
                description=f"Defender XDR alerts linked to {upn}",
                kql=_KQL_TEMPLATES["defender_alerts_user"].format(upn=upn),
                target_table="AlertEvidence",
            ))
            queries.append(SuggestedQuery(
                name=f"oauth_consents_{account.friendly_name or upn}",
                description=f"OAuth application consents by {upn}",
                kql=_KQL_TEMPLATES["oauth_app_consents"].format(upn=upn),
                target_table="AuditLogs",
            ))

        for ip_entity in ips[:3]:
            ip = ip_entity.identifier
            queries.append(SuggestedQuery(
                name=f"ip_activity_{ip.replace('.', '_')}",
                description=f"Network activity for IP {ip} in the last {hours}h",
                kql=_KQL_TEMPLATES["ip_activity"].format(ip=ip, hours=hours),
                target_table="CommonSecurityLog",
            ))
            queries.append(SuggestedQuery(
                name=f"related_incidents_{ip.replace('.', '_')}",
                description=f"Other Sentinel incidents involving {ip}",
                kql=_KQL_TEMPLATES["sentinel_related_incidents"].format(identifier=ip, hours=hours * 2),
                target_table="SecurityIncident",
            ))

        for host in hosts[:2]:
            hostname = host.identifier
            queries.append(SuggestedQuery(
                name=f"host_processes_{host.friendly_name or hostname}",
                description=f"Process execution on {hostname} in the last {hours}h",
                kql=_KQL_TEMPLATES["host_process"].format(hostname=hostname, hours=hours),
                target_table="DeviceProcessEvents",
            ))

        return queries

    # ── Investigation steps ────────────────────────────────────────────────────

    @staticmethod
    def _investigation_steps(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[EngineEntity],
        attack_patterns: list[str],
    ) -> list[str]:
        steps: list[str] = [
            "1. Preserve evidence: export incident timeline, alert details, and raw entity data",
            "2. Confirm scope: determine all affected users, hosts, and resources",
        ]

        account_entities = [e for e in entities if e.kind in ("Account",)]
        host_entities = [e for e in entities if e.kind in ("Host",)]
        ip_entities = [e for e in entities if e.kind in ("Ip",)]

        if account_entities:
            steps.append(
                f"3. Run 'atl investigate-identity {account_entities[0].identifier}' "
                "to check for sign-in anomalies, MFA gaps, and privileged role abuse"
            )

        if ip_entities:
            steps.append(
                f"4. Run 'atl resolve-entity {ip_entities[0].identifier}' "
                "to check threat intelligence and Azure resource association"
            )

        if "CredentialAccess" in attack_patterns or "InitialAccess" in attack_patterns:
            steps.append("5. Reset credentials for all involved accounts and revoke active sessions")
            steps.append("6. Review and enforce MFA via Conditional Access for affected identities")

        if "LateralMovement" in attack_patterns or "LateralMovementIndicators" in attack_patterns:
            steps.append("7. Network segment analysis: review NSG flow logs and firewall rules")
            steps.append("8. Check for new local administrator accounts or service installs on affected hosts")

        if host_entities:
            steps.append("9. Isolate affected hosts in Defender for Endpoint for forensic imaging")

        if "Exfiltration" in attack_patterns or "CommandAndControl" in attack_patterns:
            steps.append("10. Engage IR team – possible active threat actor; consider network blackholing of C2 IPs")

        steps.append("11. Document findings and update incident classification in Sentinel")
        steps.append("12. Post-incident: review detection gaps and create custom analytics rules if needed")

        return steps

    # ── Confidence assessment ──────────────────────────────────────────────────

    @staticmethod
    def _assess_confidence(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[dict[str, Any]],
    ) -> str:
        """Estimate confidence based on data richness."""
        score = 0
        if alerts:
            score += min(len(alerts), 3)  # More alerts → more signal
        if entities:
            score += min(len(entities), 3)  # More entities → more context
        if incident.get("tactics"):
            score += 1
        if incident.get("techniques"):
            score += 1
        if incident.get("description"):
            score += 1
        return "high" if score >= 6 else "medium" if score >= 3 else "low"

    # ── Utilities ──────────────────────────────────────────────────────────────

    @staticmethod
    def _time_range_hours(time_range: dict[str, str], default: int = 168) -> int:
        try:
            start = datetime.fromisoformat(time_range.get("start", "").replace("Z", "+00:00"))
            end = datetime.fromisoformat(time_range.get("end", "").replace("Z", "+00:00"))
            return max(1, int((end - start).total_seconds() / 3600))
        except (ValueError, AttributeError):
            return default
