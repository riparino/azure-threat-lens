"""Incident triage analysis – scores and prioritises Sentinel incidents."""

from __future__ import annotations

import asyncio
from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.azure.sentinel import SentinelClient
from azure_threat_lens.integrations.threat_intel.enricher import ThreatIntelEnricher
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import ThreatIntelHit
from azure_threat_lens.models.incident import Alert, AlertEntity, Incident, Severity, TriageResult

log = get_logger(__name__)

# Sentinel severity → numeric weight
_SEVERITY_SCORES: dict[str, float] = {
    "High": 9.0,
    "Medium": 6.0,
    "Low": 3.0,
    "Informational": 1.0,
}


class IncidentTriageAnalyser:
    """Scores and enriches a Sentinel incident to produce a TriageResult."""

    def __init__(self, workspace: str | None = None) -> None:
        self._sentinel = SentinelClient(workspace=workspace)
        self._ti = ThreatIntelEnricher()
        cfg = get_settings()
        self._weights: dict[str, float] = cfg.get_yaml(
            "triage", "severity_weights",
            default={
                "alert_severity": 0.35,
                "entity_risk": 0.25,
                "threat_intel_hits": 0.25,
                "recurrence": 0.15,
            },
        )
        raw_thresholds: dict[str, float] = cfg.get_yaml(
            "triage", "priority_thresholds",
            default={"critical": 8.0, "high": 6.0, "medium": 4.0, "low": 0.0},
        )
        # Convert to sorted list of (threshold, label) for easy comparison
        self._thresholds = sorted(
            [(v, k.capitalize()) for k, v in raw_thresholds.items()],
            reverse=True,
        )

    async def triage(self, incident_id: str) -> TriageResult:
        """Fetch and fully triage a Sentinel incident."""
        log.info("triage.start", incident_id=incident_id)

        incident, alerts, entities = await asyncio.gather(
            self._sentinel.get_incident(incident_id),
            self._sentinel.get_incident_alerts(incident_id),
            self._sentinel.get_incident_entities(incident_id),
        )
        incident.alerts = alerts
        incident.entities = entities

        # Enrich IP entities with threat intel
        ti_hits: dict[str, list[ThreatIntelHit]] = {}
        ip_entities = [e for e in entities if e.entity_type == "Ip"]
        if ip_entities:
            enrich_tasks = {
                e.properties.get("address", ""): self._ti.enrich_ip(e.properties.get("address", ""))
                for e in ip_entities
                if e.properties.get("address")
            }
            results = await asyncio.gather(*enrich_tasks.values(), return_exceptions=True)
            for ip, result in zip(enrich_tasks.keys(), results):
                if isinstance(result, list):
                    ti_hits[ip] = result

        score = self._compute_score(incident, alerts, entities, ti_hits)
        priority = self._score_to_label(score)
        indicators = self._extract_indicators(incident, alerts, entities, ti_hits)
        actions = self._recommend_actions(incident, alerts, entities, ti_hits)

        return TriageResult(
            incident_id=incident.incident_id,
            incident_number=incident.incident_number,
            title=incident.title,
            severity=incident.severity,
            priority_score=score,
            priority_label=priority,
            summary=self._build_summary(incident, alerts, entities),
            key_indicators=indicators,
            recommended_actions=actions,
            mitre_tactics=incident.tactics,
            mitre_techniques=incident.techniques,
            enrichment_data={
                "threat_intel": {ip: [h.model_dump() for h in hits] for ip, hits in ti_hits.items()},
                "alert_count": len(alerts),
                "entity_count": len(entities),
            },
        )

    async def triage_list(
        self,
        *,
        lookback_hours: int = 72,
        severity: Severity | None = None,
        top: int = 20,
    ) -> list[TriageResult]:
        """Fetch and triage multiple incidents."""
        incidents = await self._sentinel.list_incidents(
            lookback_hours=lookback_hours,
            severity=severity,
            top=top,
        )
        log.info("triage.list", count=len(incidents))
        tasks = [self.triage(inc.incident_id) for inc in incidents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in results if isinstance(r, TriageResult)]
        return sorted(valid, key=lambda r: r.priority_score, reverse=True)

    # ── Scoring ────────────────────────────────────────────────────────────────

    def _compute_score(
        self,
        incident: Incident,
        alerts: list[Alert],
        entities: list[AlertEntity],
        ti_hits: dict[str, list[ThreatIntelHit]],
    ) -> float:
        sev_score = _SEVERITY_SCORES.get(incident.severity.value, 1.0)

        # Entity risk: ratio of high-severity entities
        entity_risk = 0.0
        if entities:
            high_risk = sum(1 for e in entities if e.entity_type in ("Account", "Ip", "Host"))
            entity_risk = min(high_risk / len(entities) * 10, 10.0)

        # Threat intel: aggregate score across all IP hits
        all_hits = [h for hits in ti_hits.values() for h in hits]
        ti_score = ThreatIntelEnricher.aggregate_risk_score(all_hits) if all_hits else 0.0

        # Recurrence: more alerts → higher recurrence signal
        recurrence = min(len(alerts) * 2.0, 10.0)

        w = self._weights
        raw = (
            sev_score * w.get("alert_severity", 0.35)
            + entity_risk * w.get("entity_risk", 0.25)
            + ti_score * w.get("threat_intel_hits", 0.25)
            + recurrence * w.get("recurrence", 0.15)
        )
        return round(min(raw, 10.0), 2)

    def _score_to_label(self, score: float) -> str:
        for threshold, label in self._thresholds:
            if score >= threshold:
                return label
        return "Low"

    # ── Narrative helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_summary(incident: Incident, alerts: list[Alert], entities: list[AlertEntity]) -> str:
        entity_types = list({e.entity_type for e in entities})
        return (
            f"Incident #{incident.incident_number} – '{incident.title}' "
            f"({incident.severity.value} severity, {incident.status.value}). "
            f"{len(alerts)} alert(s) detected involving {len(entities)} entit{'y' if len(entities) == 1 else 'ies'} "
            f"({', '.join(entity_types) or 'none'}). "
            f"Tactics: {', '.join(incident.tactics) or 'unknown'}."
        )

    @staticmethod
    def _extract_indicators(
        incident: Incident,
        alerts: list[Alert],
        entities: list[AlertEntity],
        ti_hits: dict[str, list[ThreatIntelHit]],
    ) -> list[str]:
        indicators: list[str] = []
        if incident.tactics:
            indicators.append(f"MITRE tactics observed: {', '.join(incident.tactics)}")
        for entity in entities:
            fn = entity.friendly_name or entity.properties.get("address", "")
            if fn:
                indicators.append(f"{entity.entity_type} entity: {fn}")
        for ip, hits in ti_hits.items():
            malicious = [h for h in hits if h.malicious]
            if malicious:
                providers = ", ".join(h.provider for h in malicious)
                indicators.append(f"IP {ip} flagged as malicious by: {providers}")
        if len(alerts) > 3:
            indicators.append(f"High alert volume: {len(alerts)} correlated alerts")
        return indicators

    @staticmethod
    def _recommend_actions(
        incident: Incident,
        alerts: list[Alert],
        entities: list[AlertEntity],
        ti_hits: dict[str, list[ThreatIntelHit]],
    ) -> list[str]:
        actions: list[str] = []
        account_entities = [e for e in entities if e.entity_type == "Account"]
        ip_entities = [e for e in entities if e.entity_type == "Ip"]
        host_entities = [e for e in entities if e.entity_type == "Host"]

        if account_entities:
            actions.append("Investigate involved accounts for signs of compromise (run investigate-identity)")
        if ip_entities:
            actions.append("Resolve IP entities and cross-check threat intelligence (run resolve-entity)")
            malicious_ips = [ip for ip, hits in ti_hits.items() if any(h.malicious for h in hits)]
            if malicious_ips:
                actions.append(f"Block malicious IPs in firewall/NSG: {', '.join(malicious_ips)}")
        if host_entities:
            actions.append("Isolate affected hosts in Defender for Endpoint if compromise is confirmed")
        if "InitialAccess" in incident.tactics or "CredentialAccess" in incident.tactics:
            actions.append("Review conditional access policies and enforce MFA for impacted users")
        if incident.severity in (Severity.HIGH,):
            actions.append("Escalate to Tier 2 SOC analyst and open P1 incident ticket")
        actions.append("Preserve evidence: export raw alert data and entity timelines")
        return actions
