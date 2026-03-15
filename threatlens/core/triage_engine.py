from __future__ import annotations

from threatlens.analysis.identity_abuse import IdentityAbuseAnalyzer
from threatlens.entities.entity_resolver import EntityResolver
from threatlens.intel.enricher import ThreatIntelEnricher
from threatlens.models.incidents import Incident
from threatlens.models.investigations import InvestigationReport


class TriageEngine:
    def __init__(self) -> None:
        self._resolver = EntityResolver()
        self._identity_analysis = IdentityAbuseAnalyzer()
        self._intel = ThreatIntelEnricher()

    def triage_incident(self, incident: Incident) -> InvestigationReport:
        findings = []
        for entity in incident.entities:
            resolved = self._resolver.resolve(entity.value)
            if resolved["type"] == "identity":
                findings.extend(self._identity_analysis.analyze(resolved["data"]))
            if resolved["type"] == "network":
                self._intel.enrich(entity.value)
        guidance = [
            "Preserve logs and incident artifacts.",
            "Pivot across subscriptions with Azure Resource Graph.",
            "Validate suspicious identities and reset credentials when needed.",
        ]
        return InvestigationReport(
            report_type="incident_triage",
            target=incident.incident_id,
            summary=f"Triage completed for incident {incident.incident_id} with {len(findings)} findings.",
            findings=findings,
            guidance=guidance,
            metadata={"severity": incident.severity, "alert_count": len(incident.alerts)},
        )
