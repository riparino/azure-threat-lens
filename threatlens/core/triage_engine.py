from __future__ import annotations

from threatlens.azure.sentinel_client import SentinelClient
from threatlens.core.verdict_engine import risk_to_verdict
from threatlens.entities.entity_resolver import EntityResolver
from threatlens.models.investigations import InvestigationFinding, InvestigationReport
from threatlens.reasoning.llm_engine import LLMEngine
from threatlens.reasoning.prompt_templates import INCIDENT_PROMPT


class TriageEngine:
    def __init__(self, sentinel_client: SentinelClient, entity_resolver: EntityResolver, llm_engine: LLMEngine) -> None:
        self.sentinel_client = sentinel_client
        self.entity_resolver = entity_resolver
        self.llm_engine = llm_engine

    async def triage_incident(self, incident_id: str) -> InvestigationReport:
        incident = await self.sentinel_client.get_incident(incident_id)
        resolved_entities = [await self.entity_resolver.resolve(entity.value) for entity in incident.entities]

        risk_score = 40 if incident.severity.lower() == "medium" else 70
        risk_score += 10 if any(item.get("kind") == "ip" for item in resolved_entities) else 0
        findings = [
            InvestigationFinding(
                category="incident",
                summary=f"Incident {incident.title} has {len(incident.alerts)} linked alerts",
                severity=incident.severity,
                evidence={"incident": incident.model_dump(), "resolved_entities": resolved_entities},
            )
        ]
        summary = await self.llm_engine.summarize(INCIDENT_PROMPT, {"incident": incident.model_dump()})
        return InvestigationReport(
            report_id=f"triage-{incident_id}",
            investigation_type="incident_triage",
            target=incident_id,
            risk_score=min(risk_score, 100),
            verdict=risk_to_verdict(risk_score),
            summary=summary,
            findings=findings,
            recommendations=[
                "Validate suspicious identities and disable compromised sessions",
                "Scope related resources using Azure Resource Graph",
            ],
            metadata={"alerts_analyzed": len(incident.alerts)},
        )
