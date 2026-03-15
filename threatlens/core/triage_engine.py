"""Triage Engine – deterministic structured analysis of Sentinel incidents.

This engine analyses a Sentinel incident and its associated data without
calling any LLM. It produces a fully structured, JSON-serialisable output
that an LLM reasoning layer may later enhance.

Input:
    Sentinel incident JSON, associated alerts, entities, time range

Output schema:
    {
        "incident_id":        str,
        "summary":            str,
        "risk_level":         str,   # critical | high | medium | low
        "key_entities":       list,  # extracted, typed, prioritised entities
        "attack_hypotheses":  list,  # likely attack category + evidence
        "recommended_queries": list, # KQL queries with name/description/kql
        "investigation_steps": list, # ordered analyst playbook
        "confidence":         str    # high | medium | low
    }

The engine is intentionally LLM-free so it can run in air-gapped or
rate-limited environments and produce consistent, auditable output.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from threatlens.utils.logging import get_logger

log = get_logger(__name__)

# ── MITRE ATT&CK keyword signals ──────────────────────────────────────────────
# Maps tactic → keywords that suggest it from alert/incident text
_TACTIC_SIGNALS: dict[str, list[str]] = {
    "InitialAccess":       ["anonymous ip", "impossible travel", "unfamiliar sign-in", "spray", "brute-force", "brute force", "phish", "password spray", "token theft"],
    "Execution":           ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bash", "python", "script"],
    "Persistence":         ["scheduled task", "registry run", "startup", "service install", "autorun", "cron", "persistence"],
    "PrivilegeEscalation": ["uac bypass", "token impersonation", "sudo", "setuid", "privilege", "admin", "elevation"],
    "DefenseEvasion":      ["obfuscat", "encode", "base64", "disable antivirus", "tamper", "clear log", "stealth", "signed binary"],
    "CredentialAccess":    ["credential", "password", "lsass", "mimikatz", "kerberoast", "dcsync", "ntlm", "hash dump", "brute"],
    "Discovery":           ["net user", "whoami", "ipconfig", "arp ", "nmap", "scan", "enum", "ldap query", "directory harvest"],
    "LateralMovement":     ["psexec", "wmi", "smb", "remote desktop", "rdp", "winrm", "ssh", "pass-the-hash", "lateral"],
    "Collection":          ["archive", "compress", "zip", "staged", "clipboard", "keylog", "screenshot", "collect"],
    "Exfiltration":        ["upload", "ftp", "dns tunnel", "http post", "pastebin", "exfiltrat", "data transfer"],
    "Impact":              ["ransomware", "encrypt", "wipe", "delete", "shutdown", "ddos", "deface", "destruct"],
    "CommandAndControl":   ["c2", "beacon", "cobalt strike", "metasploit", "dns beacon", "reverse shell", "command and control"],
}

# Risk bump for particularly high-signal tactics
_HIGH_SIGNAL_TACTICS = {"CommandAndControl", "Exfiltration", "Impact", "CredentialAccess"}

# KQL query templates keyed by scenario
_KQL_TEMPLATES: dict[str, str] = {
    "user_risky_signins": """\
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "{upn}"
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, AppDisplayName, RiskLevelDuringSignIn, ClientAppUsed
| order by TimeGenerated desc""",

    "user_impossible_travel": """\
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "{upn}"
| project TimeGenerated, IPAddress, Country=tostring(LocationDetails.countryOrRegion)
| order by TimeGenerated asc
| extend PrevTime=prev(TimeGenerated), PrevCountry=prev(Country)
| where Country != PrevCountry
| extend HoursDiff=datetime_diff('hour', TimeGenerated, PrevTime)
| where HoursDiff < 4""",

    "ip_activity": """\
union CommonSecurityLog, AzureNetworkAnalytics_CL
| where TimeGenerated > ago({hours}h)
| where SourceIP == "{ip}" or DestinationIP == "{ip}"
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction, Activity, Computer
| order by TimeGenerated desc
| take 200""",

    "host_processes": """\
DeviceProcessEvents
| where TimeGenerated > ago({hours}h)
| where DeviceName contains "{hostname}"
| project TimeGenerated, DeviceName, AccountName,
          FileName, ProcessCommandLine, ParentProcessName, SHA256
| order by TimeGenerated desc
| take 200""",

    "user_defender_alerts": """\
AlertEvidence
| where TimeGenerated > ago(30d)
| where AccountUpn =~ "{upn}"
| join kind=inner AlertInfo on AlertId
| project TimeGenerated, Title, Severity, Category, AccountUpn, AttackTechniques
| order by TimeGenerated desc""",

    "related_incidents": """\
SecurityIncident
| where TimeGenerated > ago({hours}h)
| where Entities contains "{identifier}"
| project TimeGenerated, Title, Severity, Status, IncidentNumber
| order by TimeGenerated desc""",

    "oauth_consents": """\
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Consent to application"
| where InitiatedBy.user.userPrincipalName =~ "{upn}"
| project TimeGenerated, OperationName, TargetResources, Result, IPAddress
| order by TimeGenerated desc""",

    "keyvault_reads": """\
AzureDiagnostics
| where TimeGenerated > ago({hours}h)
| where ResourceType == "VAULTS" and Category == "AuditEvent"
| where OperationName == "SecretGet" or OperationName == "KeyDecrypt"
| where CallerIPAddress == "{ip}" or requestUri_s contains "{identifier}"
| project TimeGenerated, CallerIPAddress, identity_claim_oid_g, OperationName, ResultType
| order by TimeGenerated desc""",

    "rbac_changes": """\
AzureActivity
| where TimeGenerated > ago({hours}h)
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
         or OperationNameValue == "Microsoft.Authorization/roleAssignments/delete"
| where Caller == "{upn}" or ResourceId contains "{identifier}"
| project TimeGenerated, Caller, OperationNameValue, ResourceId, ActivityStatus
| order by TimeGenerated desc""",
}


# ── Pydantic output models ─────────────────────────────────────────────────────

class KeyEntity(BaseModel):
    """An extracted and typed entity from the incident."""

    kind: str                                         # Ip | Account | Host | FileHash | Url | AzureResource
    identifier: str
    friendly_name: str = ""
    source: str = ""                                  # "alert" | "incident" | "entity_list"
    frequency: int = 1                                # How many alerts reference this entity
    risk_indicators: list[str] = Field(default_factory=list)


class AttackHypothesis(BaseModel):
    """A potential attack category with supporting evidence."""

    category: str                                     # e.g. "CredentialAccess"
    description: str                                  # Human-readable attack description
    evidence: list[str] = Field(default_factory=list) # Supporting signals from the data
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: str = "medium"                        # high | medium | low


class RecommendedQuery(BaseModel):
    name: str
    description: str
    kql: str
    target_table: str = ""


class TriageOutput(BaseModel):
    """Structured triage output – always JSON-serialisable, no LLM dependency."""

    incident_id: str
    summary: str
    risk_level: str                                    # critical | high | medium | low
    key_entities: list[KeyEntity]
    attack_hypotheses: list[AttackHypothesis]
    recommended_queries: list[RecommendedQuery]
    investigation_steps: list[str]
    confidence: str                                    # high | medium | low
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Input schema ──────────────────────────────────────────────────────────────

class TriageInput(BaseModel):
    """Input to the TriageEngine."""

    incident: dict[str, Any]                          # Sentinel incident JSON
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    entities: list[dict[str, Any]] = Field(default_factory=list)
    time_range: dict[str, str] = Field(default_factory=dict)


# ── Engine ─────────────────────────────────────────────────────────────────────

class TriageEngine:
    """Deterministic incident triage engine.

    Produces structured analysis from raw Sentinel data without any LLM calls.
    Output is stable, auditable, and suitable for SOAR automation.

    To add LLM reasoning on top, pass the TriageOutput to the LLMEngine in the
    reasoning module.
    """

    async def run(self, data: TriageInput) -> TriageOutput:
        incident = data.incident
        incident_id = incident.get("incidentId", incident.get("incident_id", "unknown"))
        log.info("triage_engine.run", incident_id=incident_id)

        key_entities = self._extract_key_entities(data.alerts, data.entities)
        attack_hypotheses = self._build_attack_hypotheses(incident, data.alerts, key_entities)
        tactics, techniques = self._extract_mitre(incident, data.alerts)
        risk_level = self._assess_risk(incident, data.alerts, attack_hypotheses)
        summary = self._build_summary(incident, data.alerts, key_entities, risk_level)
        queries = self._generate_queries(key_entities, data.time_range, incident)
        steps = self._build_investigation_steps(key_entities, attack_hypotheses, incident)
        confidence = self._assess_confidence(incident, data.alerts, data.entities)

        return TriageOutput(
            incident_id=incident_id,
            summary=summary,
            risk_level=risk_level,
            key_entities=key_entities,
            attack_hypotheses=attack_hypotheses,
            recommended_queries=queries,
            investigation_steps=steps,
            confidence=confidence,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
        )

    # ── Entity extraction ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_key_entities(
        alerts: list[dict[str, Any]],
        raw_entities: list[dict[str, Any]],
    ) -> list[KeyEntity]:
        """Extract and deduplicate entities, counting frequency across alerts."""
        seen: dict[str, KeyEntity] = {}

        def _add(kind: str, identifier: str, friendly: str, source: str) -> None:
            if not identifier:
                return
            key = f"{kind}:{identifier.lower()}"
            if key in seen:
                seen[key].frequency += 1
            else:
                seen[key] = KeyEntity(
                    kind=kind,
                    identifier=identifier,
                    friendly_name=friendly or identifier,
                    source=source,
                )

        # From explicit entity list
        for ent in raw_entities:
            kind = ent.get("entityType", ent.get("kind", "Unknown"))
            props = ent.get("properties", ent)
            identifier = (
                props.get("address")
                or props.get("userPrincipalName")
                or props.get("accountName")
                or props.get("hostName")
                or props.get("url")
                or props.get("hashValue")
                or ent.get("identifier", "")
                or ent.get("friendly_name", "")
            )
            friendly = props.get("friendlyName", ent.get("friendly_name", ""))
            _add(kind, str(identifier), str(friendly), "entity_list")

        # From alert extended properties (supplement entity list)
        for alert in alerts:
            ext = alert.get("extendedProperties", alert.get("extended_properties", {}))
            for field, kind in [
                ("CompromisedEntity", "Account"),
                ("AttackerIP", "Ip"),
                ("TargetDevice", "Host"),
            ]:
                if val := ext.get(field):
                    _add(kind, str(val), str(val), "alert")

        entities = list(seen.values())
        # Sort: high-frequency entities first, then by kind priority
        kind_priority = {"Account": 0, "Ip": 1, "Host": 2, "AzureResource": 3}
        entities.sort(key=lambda e: (-(e.frequency), kind_priority.get(e.kind, 9)))
        return entities

    # ── Attack hypotheses ──────────────────────────────────────────────────────

    def _build_attack_hypotheses(
        self,
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        key_entities: list[KeyEntity],
    ) -> list[AttackHypothesis]:
        """Build attack hypotheses from tactic signal detection."""
        corpus = self._build_corpus(incident, alerts)
        detected: dict[str, list[str]] = {}  # tactic → evidence list

        for tactic, keywords in _TACTIC_SIGNALS.items():
            evidence = [kw for kw in keywords if kw.lower() in corpus]
            if evidence:
                detected[tactic] = evidence

        # Add tactics explicitly listed in incident/alerts
        explicit_tactics = set(incident.get("tactics", []))
        for alert in alerts:
            explicit_tactics.update(alert.get("tactics", []))
        for tactic in explicit_tactics:
            if tactic not in detected:
                detected[tactic] = ["Explicitly listed in Sentinel data"]

        # Entity-based hypotheses
        entity_kinds = {e.kind for e in key_entities}
        if "Account" in entity_kinds and "Ip" in entity_kinds:
            detected.setdefault("InitialAccess", []).append("Account + external IP combination")
        if len([e for e in key_entities if e.kind == "Host"]) > 1:
            detected.setdefault("LateralMovement", []).append("Multiple hosts involved")

        # Convert to AttackHypothesis objects
        hypotheses = []
        for tactic, evidence in detected.items():
            hypotheses.append(AttackHypothesis(
                category=tactic,
                description=_tactic_description(tactic),
                evidence=list(dict.fromkeys(evidence)),  # deduplicate
                mitre_tactics=[tactic],
                confidence="high" if len(evidence) >= 3 else "medium" if len(evidence) >= 1 else "low",
            ))

        # Sort: high-signal tactics first
        hypotheses.sort(key=lambda h: (h.category not in _HIGH_SIGNAL_TACTICS, -len(h.evidence)))
        return hypotheses

    # ── MITRE extraction ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_mitre(
        incident: dict[str, Any], alerts: list[dict[str, Any]]
    ) -> tuple[list[str], list[str]]:
        tactics: list[str] = list(incident.get("tactics", []))
        techniques: list[str] = list(incident.get("techniques", []))
        for alert in alerts:
            for t in alert.get("tactics", []):
                if t not in tactics:
                    tactics.append(t)
            for t in alert.get("techniques", alert.get("mitreTechniques", [])):
                if t not in techniques:
                    techniques.append(t)
        return tactics, techniques

    # ── Risk assessment ────────────────────────────────────────────────────────

    @staticmethod
    def _assess_risk(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        hypotheses: list[AttackHypothesis],
    ) -> str:
        severity_rank = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1}
        rank = severity_rank.get(incident.get("severity", "Informational"), 1)

        high_signal = {h.category for h in hypotheses if h.category in _HIGH_SIGNAL_TACTICS}
        if high_signal:
            rank = min(rank + 1, 4)
        if len(alerts) >= 5:
            rank = min(rank + 1, 4)
        if len(hypotheses) >= 4:
            rank = min(rank + 1, 4)

        return {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(rank, "low")

    # ── Summary ────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_summary(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        key_entities: list[KeyEntity],
        risk_level: str,
    ) -> str:
        inc_num = incident.get("incidentNumber", incident.get("incident_number", "?"))
        title = incident.get("title", "Unknown")
        severity = incident.get("severity", "Unknown")
        entity_summary = ", ".join(
            f"{e.kind}:{e.identifier}" for e in key_entities[:4]
        ) or "none identified"
        tactics = ", ".join(incident.get("tactics", [])) or "unknown"
        return (
            f"Incident #{inc_num} – '{title}' ({severity} severity, {risk_level.upper()} risk). "
            f"{len(alerts)} correlated alert(s). Key entities: {entity_summary}. "
            f"Primary tactics: {tactics}."
        )

    # ── KQL query generation ───────────────────────────────────────────────────

    def _generate_queries(
        self,
        key_entities: list[KeyEntity],
        time_range: dict[str, str],
        incident: dict[str, Any],
    ) -> list[RecommendedQuery]:
        queries: list[RecommendedQuery] = []
        hours = self._time_range_to_hours(time_range, default=168)

        accounts = [e for e in key_entities if e.kind in ("Account",)]
        ips = [e for e in key_entities if e.kind in ("Ip",)]
        hosts = [e for e in key_entities if e.kind in ("Host",)]
        incident_id = incident.get("incidentId", "?")

        for account in accounts[:3]:
            upn = account.identifier
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", upn)[:20]
            queries.append(RecommendedQuery(
                name=f"risky_signins_{safe_name}",
                description=f"High-risk Entra ID sign-in events for {upn}",
                kql=_KQL_TEMPLATES["user_risky_signins"].format(upn=upn),
                target_table="SigninLogs",
            ))
            queries.append(RecommendedQuery(
                name=f"impossible_travel_{safe_name}",
                description=f"Impossible travel detection for {upn}",
                kql=_KQL_TEMPLATES["user_impossible_travel"].format(upn=upn),
                target_table="SigninLogs",
            ))
            queries.append(RecommendedQuery(
                name=f"defender_alerts_{safe_name}",
                description=f"Defender XDR alerts for {upn}",
                kql=_KQL_TEMPLATES["user_defender_alerts"].format(upn=upn),
                target_table="AlertEvidence",
            ))
            queries.append(RecommendedQuery(
                name=f"oauth_consents_{safe_name}",
                description=f"OAuth application consents by {upn}",
                kql=_KQL_TEMPLATES["oauth_consents"].format(upn=upn),
                target_table="AuditLogs",
            ))
            queries.append(RecommendedQuery(
                name=f"rbac_changes_{safe_name}",
                description=f"RBAC changes by or affecting {upn}",
                kql=_KQL_TEMPLATES["rbac_changes"].format(upn=upn, identifier=upn, hours=hours),
                target_table="AzureActivity",
            ))

        for ip_ent in ips[:3]:
            ip = ip_ent.identifier
            safe_ip = ip.replace(".", "_")
            queries.append(RecommendedQuery(
                name=f"ip_activity_{safe_ip}",
                description=f"Network activity for IP {ip}",
                kql=_KQL_TEMPLATES["ip_activity"].format(ip=ip, hours=hours),
                target_table="CommonSecurityLog",
            ))
            queries.append(RecommendedQuery(
                name=f"related_incidents_{safe_ip}",
                description=f"Other Sentinel incidents involving {ip}",
                kql=_KQL_TEMPLATES["related_incidents"].format(identifier=ip, hours=hours * 2),
                target_table="SecurityIncident",
            ))

        for host in hosts[:2]:
            hostname = host.identifier
            safe_host = re.sub(r"[^a-zA-Z0-9]", "_", hostname)[:20]
            queries.append(RecommendedQuery(
                name=f"host_processes_{safe_host}",
                description=f"Process execution on {hostname}",
                kql=_KQL_TEMPLATES["host_processes"].format(hostname=hostname, hours=hours),
                target_table="DeviceProcessEvents",
            ))

        return queries

    # ── Investigation steps ────────────────────────────────────────────────────

    @staticmethod
    def _build_investigation_steps(
        key_entities: list[KeyEntity],
        hypotheses: list[AttackHypothesis],
        incident: dict[str, Any],
    ) -> list[str]:
        steps: list[str] = [
            "1. Preserve evidence: export incident JSON, alert details, and entity timelines",
            "2. Verify scope: confirm all affected users, hosts, and Azure resources",
        ]
        step = 3

        accounts = [e for e in key_entities if e.kind == "Account"]
        ips = [e for e in key_entities if e.kind == "Ip"]
        hosts = [e for e in key_entities if e.kind == "Host"]
        hypothesis_cats = {h.category for h in hypotheses}

        if accounts:
            steps.append(
                f"{step}. Run `threatlens investigate-identity {accounts[0].identifier}` "
                "to analyse sign-in anomalies, MFA gaps, and privilege assignments"
            )
            step += 1

        if ips:
            steps.append(
                f"{step}. Run `threatlens resolve-entity {ips[0].identifier}` "
                "to check threat intelligence and Azure resource association"
            )
            step += 1

        if "CredentialAccess" in hypothesis_cats or "InitialAccess" in hypothesis_cats:
            steps.append(f"{step}. Reset credentials and revoke active sessions for all involved accounts")
            step += 1
            steps.append(f"{step}. Enforce MFA via Conditional Access for affected identities")
            step += 1

        if "LateralMovement" in hypothesis_cats:
            steps.append(f"{step}. Review NSG flow logs and firewall rules for lateral movement paths")
            step += 1
            steps.append(f"{step}. Check for new local admin accounts or service installations on affected hosts")
            step += 1

        if hosts:
            steps.append(f"{step}. Isolate affected hosts in Defender for Endpoint for forensic imaging")
            step += 1

        if "CommandAndControl" in hypothesis_cats or "Exfiltration" in hypothesis_cats:
            steps.append(
                f"{step}. URGENT – Engage IR team. Possible active threat actor. "
                "Consider blocking C2 IPs at network perimeter."
            )
            step += 1

        if "PrivilegeEscalation" in hypothesis_cats:
            steps.append(
                f"{step}. Run `threatlens investigate-resource <subscription_id>` "
                "to review RBAC changes and role assignments"
            )
            step += 1

        steps.append(f"{step}. Document all findings and update incident classification in Sentinel")
        step += 1
        steps.append(f"{step}. Post-incident: review detection gaps and create custom analytics rules if needed")

        return steps

    # ── Confidence ────────────────────────────────────────────────────────────

    @staticmethod
    def _assess_confidence(
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[dict[str, Any]],
    ) -> str:
        score = 0
        if alerts:
            score += min(len(alerts), 3)
        if entities:
            score += min(len(entities), 3)
        if incident.get("tactics"):
            score += 1
        if incident.get("techniques"):
            score += 1
        if incident.get("description"):
            score += 1
        return "high" if score >= 6 else "medium" if score >= 3 else "low"

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_corpus(incident: dict[str, Any], alerts: list[dict[str, Any]]) -> str:
        parts = [
            incident.get("title", ""),
            incident.get("description", ""),
            *[a.get("alertDisplayName", a.get("title", "")) for a in alerts],
            *[a.get("description", "") for a in alerts],
        ]
        return " ".join(parts).lower()

    @staticmethod
    def _time_range_to_hours(time_range: dict[str, str], default: int = 168) -> int:
        try:
            start = datetime.fromisoformat(time_range["start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(time_range["end"].replace("Z", "+00:00"))
            return max(1, int((end - start).total_seconds() / 3600))
        except (KeyError, ValueError):
            return default


# ── Tactic descriptions ────────────────────────────────────────────────────────

_TACTIC_DESCRIPTIONS: dict[str, str] = {
    "InitialAccess": "Attacker gaining initial foothold – credential compromise, phishing, or token theft",
    "Execution": "Malicious code execution – PowerShell, scripts, or living-off-the-land binaries",
    "Persistence": "Establishing persistence mechanisms to survive reboots or credential resets",
    "PrivilegeEscalation": "Gaining elevated permissions within the environment",
    "DefenseEvasion": "Evading security controls, antivirus, or logging mechanisms",
    "CredentialAccess": "Stealing credentials, tokens, or hashes from the environment",
    "Discovery": "Reconnaissance of the environment – enumerating users, hosts, or resources",
    "LateralMovement": "Moving between hosts or services within the environment",
    "Collection": "Gathering data of interest before exfiltration",
    "Exfiltration": "Transferring sensitive data out of the environment",
    "Impact": "Disrupting availability, integrity, or confidentiality – ransomware, wiping, DoS",
    "CommandAndControl": "Communication with attacker-controlled infrastructure",
}


def _tactic_description(tactic: str) -> str:
    return _TACTIC_DESCRIPTIONS.get(tactic, f"Possible {tactic} activity detected")
