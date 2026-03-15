from __future__ import annotations

from collections.abc import Callable

from threatlens.azure.activity_log_client import ActivityLogClient
from threatlens.analysis.privilege_escalation import PrivilegeEscalationAnalyzer
from threatlens.analysis.resource_access_analysis import ResourceAccessAnalyzer
from threatlens.analysis.token_abuse import TokenAbuseAnalyzer
from threatlens.core.verdict_engine import VerdictEngine
from threatlens.entities.azure_resource_resolver import AzureResourceResolver
from threatlens.entities.entity_resolver import EntityResolver
from threatlens.entities.identity_resolver import IdentityResolver
from threatlens.models.investigations import InvestigationReport


class InvestigationEngine:
    """Module registry pattern to add new investigation routines without changing core orchestration."""

    def __init__(self) -> None:
        self._entity_resolver = EntityResolver()
        self._identity_resolver = IdentityResolver()
        self._resource_resolver = AzureResourceResolver()
        self._activity_logs = ActivityLogClient()
        self._token = TokenAbuseAnalyzer()
        self._privesc = PrivilegeEscalationAnalyzer()
        self._resource_access = ResourceAccessAnalyzer()
        self._verdict = VerdictEngine()
        self._modules: dict[str, Callable[[str], InvestigationReport]] = {
            "resolve_entity": self.resolve_entity,
            "investigate_identity": self.investigate_identity,
            "investigate_resource": self.investigate_resource,
        }

    def register_module(self, name: str, handler: Callable[[str], InvestigationReport]) -> None:
        self._modules[name] = handler

    def run_module(self, name: str, target: str) -> InvestigationReport:
        if name not in self._modules:
            raise ValueError(f"Unknown investigation module: {name}")
        return self._modules[name](target)

    def resolve_entity(self, entity: str) -> InvestigationReport:
        resolved = self._entity_resolver.resolve(entity)
        return InvestigationReport(
            report_type="entity_resolution",
            target=entity,
            summary=f"Resolved entity as {resolved['type']}",
            findings=[],
            guidance=["Use resolved context to pivot related identities, IPs, and resources."],
            metadata=resolved,
        )

    def investigate_identity(self, identity: str) -> InvestigationReport:
        ctx = self._identity_resolver.resolve(identity)
        findings = []
        if not ctx.get("mfaRegistered", False):
            findings.append("MFA not registered")
        risk = str(ctx.get("riskLevel", "low"))
        return InvestigationReport(
            report_type="identity_investigation",
            target=identity,
            summary=f"Identity risk level: {risk}",
            risk_score=75 if risk in {"high", "medium"} else 20,
            findings=[],
            guidance=["Review sign-in logs", "Validate conditional access", "Review privileged role assignment history"],
            metadata={"identity": ctx, "raw_findings": findings},
        )

    def investigate_resource(self, resource_id: str) -> InvestigationReport:
        context = self._resource_resolver.resolve(resource_id)
        events = self._activity_logs.query_resource_activity(resource_id)
        findings = [
            *self._token.analyze(events),
            *self._privesc.analyze(events),
            *self._resource_access.analyze(context),
        ]
        score = self._verdict.score(findings)
        return InvestigationReport(
            report_type="resource_investigation",
            target=resource_id,
            summary=f"Resource analyzed with {len(findings)} findings.",
            risk_score=score,
            findings=findings,
            guidance=["Validate role assignments", "Review write operations", "Verify resource exposure and data paths"],
            metadata={"resource_context": context, "activity_events": events},
        )
