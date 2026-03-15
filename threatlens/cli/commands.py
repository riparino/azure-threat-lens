from __future__ import annotations

import json

import anyio
import typer

from threatlens.analysis.identity_abuse import analyze_identity_abuse
from threatlens.analysis.privilege_escalation import analyze_privilege_escalation
from threatlens.analysis.resource_access_analysis import analyze_resource_access
from threatlens.analysis.token_abuse import analyze_token_abuse
from threatlens.azure.activity_log_client import ActivityLogClient
from threatlens.azure.graph_client import GraphClient
from threatlens.azure.resource_graph_client import ResourceGraphClient
from threatlens.azure.sentinel_client import SentinelClient
from threatlens.core.investigation_engine import InvestigationEngine
from threatlens.core.triage_engine import TriageEngine
from threatlens.core.verdict_engine import risk_to_verdict
from threatlens.entities.azure_resource_resolver import AzureResourceResolver
from threatlens.entities.entity_resolver import EntityResolver
from threatlens.entities.identity_resolver import IdentityResolver
from threatlens.entities.network_resolver import NetworkResolver
from threatlens.intel.abuseipdb_client import AbuseIPDBClient
from threatlens.intel.greynoise_client import GreyNoiseClient
from threatlens.intel.virustotal_client import VirusTotalClient
from threatlens.models.investigations import InvestigationFinding, InvestigationReport
from threatlens.reasoning.llm_engine import LLMEngine
from threatlens.utils.config import settings


def _build_entity_resolver() -> EntityResolver:
    network = NetworkResolver(
        VirusTotalClient(settings.virustotal_api_key),
        GreyNoiseClient(settings.greynoise_api_key),
        AbuseIPDBClient(settings.abuseipdb_api_key),
    )
    return EntityResolver(
        identity_resolver=IdentityResolver(GraphClient()),
        azure_resource_resolver=AzureResourceResolver(ResourceGraphClient()),
        network_resolver=network,
    )


def _print_report(report: InvestigationReport) -> None:
    typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))


def triage_incident(incident_id: str) -> None:
    async def _run() -> None:
        engine = TriageEngine(SentinelClient(), _build_entity_resolver(), LLMEngine())
        report = await engine.triage_incident(incident_id)
        _print_report(report)

    anyio.run(_run)


def resolve_entity(entity: str) -> None:
    async def _run() -> None:
        resolved = await _build_entity_resolver().resolve(entity)
        report = InvestigationReport(
            report_id=f"resolve-{entity}",
            investigation_type="entity_resolution",
            target=entity,
            risk_score=35,
            verdict=risk_to_verdict(35),
            summary="Entity resolution complete",
            findings=[
                InvestigationFinding(
                    category=resolved["kind"],
                    summary=f"Resolved {entity} as {resolved['kind']}",
                    severity="medium",
                    evidence=resolved,
                )
            ],
            recommendations=["Pivot into related entities and telemetry sources"],
        )
        _print_report(report)

    anyio.run(_run)


def investigate_identity(identity: str) -> None:
    async def _run() -> None:
        graph = GraphClient()
        profile = await graph.get_identity_profile(identity)
        findings = analyze_identity_abuse(profile) + analyze_token_abuse(identity)
        risk_score = min(100, 40 + len(findings) * 12)
        report = InvestigationReport(
            report_id=f"identity-{identity}",
            investigation_type="identity_abuse",
            target=identity,
            risk_score=risk_score,
            verdict=risk_to_verdict(risk_score),
            summary="Identity investigation complete",
            findings=[
                InvestigationFinding(
                    category="identity",
                    summary=item,
                    severity="high" if "risk" in item.lower() else "medium",
                    evidence={"identity": identity, "profile": profile},
                )
                for item in findings
            ],
            recommendations=["Enforce MFA", "Rotate tokens and review privileged role grants"],
        )
        _print_report(report)

    anyio.run(_run)


def investigate_resource(resource_id: str) -> None:
    async def _run() -> None:
        resource_graph = ResourceGraphClient()
        activity = ActivityLogClient()
        resource = await resource_graph.get_resource(resource_id)
        resource["related"] = await resource_graph.search_related_resources(resource_id)
        logs = await activity.list_activity(resource_id)

        findings = analyze_resource_access(resource) + analyze_privilege_escalation(logs)
        risk_score = min(100, 30 + len(findings) * 15)
        report = InvestigationReport(
            report_id=f"resource-{resource_id}",
            investigation_type="resource_investigation",
            target=resource_id,
            risk_score=risk_score,
            verdict=risk_to_verdict(risk_score),
            summary="Azure resource investigation complete",
            findings=[
                InvestigationFinding(
                    category="resource",
                    summary=item,
                    severity="high" if "role" in item.lower() else "medium",
                    evidence={"resource": resource, "activity_log": logs},
                )
                for item in findings
            ],
            recommendations=["Review privileged access paths", "Harden resource configuration baseline"],
        )
        _print_report(report)

    anyio.run(_run)


def register_default_modules(engine: InvestigationEngine) -> None:
    async def _identity_module(target: str) -> InvestigationReport:
        graph = GraphClient()
        profile = await graph.get_identity_profile(target)
        issues = analyze_identity_abuse(profile)
        score = min(100, 35 + len(issues) * 15)
        return InvestigationReport(
            report_id=f"mod-identity-{target}",
            investigation_type="identity_abuse",
            target=target,
            risk_score=score,
            verdict=risk_to_verdict(score),
            summary="Identity module output",
            findings=[
                InvestigationFinding(category="identity", summary=issue, severity="high", evidence=profile)
                for issue in issues
            ],
            recommendations=["Review conditional access policy and session controls"],
        )

    engine.register_module("identity", _identity_module)
