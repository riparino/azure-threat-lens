from __future__ import annotations

from threatlens.azure.graph_client import GraphClient
from threatlens.azure.resource_graph_client import ResourceGraphClient
from threatlens.azure.sentinel_client import SentinelClient
from threatlens.core.investigation_engine import InvestigationEngine
from threatlens.core.triage_engine import TriageEngine
from threatlens.entities.azure_resource_resolver import AzureResourceResolver
from threatlens.entities.entity_resolver import EntityResolver
from threatlens.entities.identity_resolver import IdentityResolver
from threatlens.entities.network_resolver import NetworkResolver
from threatlens.intel.abuseipdb_client import AbuseIPDBClient
from threatlens.intel.greynoise_client import GreyNoiseClient
from threatlens.intel.virustotal_client import VirusTotalClient
from threatlens.reasoning.llm_engine import LLMEngine


async def test_triage_engine_returns_structured_report() -> None:
    resolver = EntityResolver(
        IdentityResolver(GraphClient()),
        AzureResourceResolver(ResourceGraphClient()),
        NetworkResolver(VirusTotalClient(), GreyNoiseClient(), AbuseIPDBClient()),
    )
    engine = TriageEngine(SentinelClient(), resolver, LLMEngine())

    report = await engine.triage_incident("inc-123")

    assert report.investigation_type == "incident_triage"
    assert report.risk_score >= 70
    assert report.findings


async def test_investigation_engine_is_extensible() -> None:
    engine = InvestigationEngine()

    async def module(target: str):
        from threatlens.models.investigations import InvestigationReport

        return InvestigationReport(
            report_id="x",
            investigation_type="custom",
            target=target,
            risk_score=10,
            verdict="low",
            summary="ok",
        )

    engine.register_module("custom", module)
    report = await engine.run("custom", "item-1")

    assert report.investigation_type == "custom"
    assert report.target == "item-1"
