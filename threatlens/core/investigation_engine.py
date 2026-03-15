"""Investigation engine – orchestrates full multi-module investigation workflows.

Coordinates triage → entity resolution → deep analysis → verdict, collecting
all results into a unified investigation report.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class InvestigationConfig(BaseModel):
    lookback_hours: int = 72
    max_entities: int = 20
    run_identity_analysis: bool = True
    run_resource_analysis: bool = True
    run_privilege_analysis: bool = True
    run_token_analysis: bool = True
    run_threat_intel: bool = True
    run_defender: bool = True
    use_llm: bool = False  # LLM enhancement is opt-in


class InvestigationReport(BaseModel):
    incident_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    triage: dict[str, Any] = Field(default_factory=dict)
    resolved_entities: list[dict[str, Any]] = Field(default_factory=list)
    identity_analysis: list[dict[str, Any]] = Field(default_factory=list)
    resource_analysis: list[dict[str, Any]] = Field(default_factory=list)
    privilege_analysis: dict[str, Any] = Field(default_factory=dict)
    token_analysis: dict[str, Any] = Field(default_factory=dict)
    defender_alerts: list[dict[str, Any]] = Field(default_factory=list)
    verdict: dict[str, Any] = Field(default_factory=dict)
    llm_analysis: str | None = None
    errors: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class InvestigationEngine:
    """Orchestrates the full investigation pipeline for a Sentinel incident."""

    def __init__(self, cfg: InvestigationConfig | None = None) -> None:
        self._cfg = cfg or InvestigationConfig()

    async def run(self, incident_id: str, workspace: str | None = None) -> InvestigationReport:
        """Run a full investigation for a Sentinel incident.

        Phases:
          1. Fetch incident + alerts + entities from Sentinel
          2. Run deterministic triage
          3. Resolve all key entities concurrently
          4. Run deep analysis modules concurrently
          5. Render final verdict
          6. Optionally enhance with LLM
        """
        log.info("investigation_engine.run", incident_id=incident_id)
        report = InvestigationReport(incident_id=incident_id)

        # ── Phase 1: Fetch incident data ──────────────────────────────────────
        try:
            incident, alerts, raw_entities = await self._fetch_incident_data(
                incident_id, workspace
            )
        except Exception as exc:
            log.error("investigation_engine.fetch_failed", error=str(exc))
            report.errors.append(f"Failed to fetch incident data: {exc}")
            report.completed_at = datetime.now(timezone.utc)
            return report

        # ── Phase 2: Triage ───────────────────────────────────────────────────
        try:
            report.triage = await self._run_triage(incident, alerts, raw_entities)
        except Exception as exc:
            log.error("investigation_engine.triage_failed", error=str(exc))
            report.errors.append(f"Triage failed: {exc}")

        # ── Phase 3: Entity resolution ────────────────────────────────────────
        key_entities: list[dict[str, Any]] = report.triage.get("key_entities", [])
        identifiers = [e.get("identifier", "") for e in key_entities if e.get("identifier")]
        if identifiers:
            try:
                report.resolved_entities = await self._resolve_entities(
                    identifiers[: self._cfg.max_entities]
                )
            except Exception as exc:
                log.error("investigation_engine.resolution_failed", error=str(exc))
                report.errors.append(f"Entity resolution failed: {exc}")

        # ── Phase 4: Deep analysis (concurrent) ──────────────────────────────
        analysis_tasks: dict[str, asyncio.Task[Any]] = {}
        accounts = [
            e.get("identifier", "")
            for e in key_entities
            if e.get("kind") in ("account", "Account") and e.get("identifier")
        ]
        resource_ids = [
            e.get("identifier", "")
            for e in key_entities
            if e.get("kind") in ("azure_resource", "AzureResource") and e.get("identifier")
        ]

        if self._cfg.run_identity_analysis and accounts:
            analysis_tasks["identity"] = asyncio.create_task(
                self._run_identity_analysis(accounts)
            )
        if self._cfg.run_resource_analysis and resource_ids:
            analysis_tasks["resource"] = asyncio.create_task(
                self._run_resource_analysis(resource_ids)
            )
        if self._cfg.run_privilege_analysis:
            analysis_tasks["privilege"] = asyncio.create_task(
                self._run_privilege_analysis(accounts)
            )
        if self._cfg.run_token_analysis and accounts:
            analysis_tasks["token"] = asyncio.create_task(
                self._run_token_analysis(accounts)
            )
        if self._cfg.run_defender and accounts:
            analysis_tasks["defender"] = asyncio.create_task(
                self._run_defender(accounts)
            )

        if analysis_tasks:
            results = await asyncio.gather(
                *analysis_tasks.values(), return_exceptions=True
            )
            for key, result in zip(analysis_tasks.keys(), results):
                if isinstance(result, Exception):
                    log.error(f"investigation_engine.{key}_failed", error=str(result))
                    report.errors.append(f"{key} analysis failed: {result}")
                else:
                    if key == "identity":
                        report.identity_analysis = result  # type: ignore[assignment]
                    elif key == "resource":
                        report.resource_analysis = result  # type: ignore[assignment]
                    elif key == "privilege":
                        report.privilege_analysis = result  # type: ignore[assignment]
                    elif key == "token":
                        report.token_analysis = result  # type: ignore[assignment]
                    elif key == "defender":
                        report.defender_alerts = result  # type: ignore[assignment]

        # ── Phase 5: Verdict ──────────────────────────────────────────────────
        try:
            report.verdict = await self._render_verdict(report)
        except Exception as exc:
            log.error("investigation_engine.verdict_failed", error=str(exc))
            report.errors.append(f"Verdict rendering failed: {exc}")

        # ── Phase 6: Optional LLM enhancement ────────────────────────────────
        if self._cfg.use_llm:
            try:
                report.llm_analysis = await self._run_llm(report)
            except Exception as exc:
                log.warning("investigation_engine.llm_failed", error=str(exc))
                report.errors.append(f"LLM analysis failed (non-fatal): {exc}")

        report.completed_at = datetime.now(timezone.utc)
        log.info(
            "investigation_engine.complete",
            incident_id=incident_id,
            disposition=report.verdict.get("disposition"),
            errors=len(report.errors),
        )
        return report

    # ── Private phase methods ──────────────────────────────────────────────────

    async def _fetch_incident_data(
        self, incident_id: str, workspace: str | None
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        from threatlens.azure.sentinel_client import SentinelClient

        client = SentinelClient(workspace=workspace)
        async with client:
            incident = (await client.get_incident(incident_id)).model_dump(mode="json")
            alerts = [
                a.model_dump(mode="json")
                for a in await client.get_incident_alerts(incident_id)
            ]
            entities = [
                e.model_dump(mode="json")
                for e in await client.get_incident_entities(incident_id)
            ]
        return incident, alerts, entities

    async def _run_triage(
        self,
        incident: dict[str, Any],
        alerts: list[dict[str, Any]],
        entities: list[dict[str, Any]],
    ) -> dict[str, Any]:
        from threatlens.core.triage_engine import TriageEngine, TriageInput
        from threatlens.models.incidents import Alert, Incident
        from threatlens.models.entities import RawEntity

        inc_model = Incident.model_validate(incident)
        alert_models = [Alert.model_validate(a) for a in alerts]
        entity_models = [RawEntity.model_validate(e) for e in entities]

        engine = TriageEngine()
        result = await engine.run(
            TriageInput(
                incident=inc_model,
                alerts=alert_models,
                entities=entity_models,
            )
        )
        return result.model_dump(mode="json")

    async def _resolve_entities(
        self, identifiers: list[str]
    ) -> list[dict[str, Any]]:
        from threatlens.entities.entity_resolver import EntityResolver

        resolver = EntityResolver()
        tasks = [resolver.resolve(ident) for ident in identifiers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        resolved = []
        for r in results:
            if isinstance(r, Exception):
                log.warning("investigation_engine.resolve_entity_failed", error=str(r))
            else:
                resolved.append(r.model_dump(mode="json"))  # type: ignore[union-attr]
        return resolved

    async def _run_identity_analysis(
        self, accounts: list[str]
    ) -> list[dict[str, Any]]:
        from threatlens.analysis.identity_abuse import IdentityAbuseAnalyser

        analyser = IdentityAbuseAnalyser()
        results = []
        for account in accounts[:5]:  # cap at 5 accounts
            result = await analyser.investigate(
                account, lookback_days=self._cfg.lookback_hours // 24
            )
            results.append(result.model_dump(mode="json"))
        return results

    async def _run_resource_analysis(
        self, resource_ids: list[str]
    ) -> list[dict[str, Any]]:
        from threatlens.analysis.resource_access_analysis import ResourceAccessAnalyser

        analyser = ResourceAccessAnalyser()
        results = []
        for rid in resource_ids[:10]:  # cap at 10 resources
            result = await analyser.analyse_resource(
                rid, lookback_hours=self._cfg.lookback_hours
            )
            results.append(result)
        return results

    async def _run_privilege_analysis(
        self, accounts: list[str]
    ) -> dict[str, Any]:
        from threatlens.analysis.privilege_escalation import PrivilegeEscalationAnalyser

        analyser = PrivilegeEscalationAnalyser()
        all_escalations: list[dict[str, Any]] = []
        for account in accounts[:5]:
            escalations = await analyser.find_recent_escalations(
                caller=account, lookback_hours=self._cfg.lookback_hours
            )
            all_escalations.extend(escalations)
        return {
            "escalation_count": len(all_escalations),
            "escalations": all_escalations[:20],
            "findings": [
                f"Found {len(all_escalations)} privilege escalation event(s)"
            ] if all_escalations else [],
            "risk_score": min(len(all_escalations) * 1.5, 10.0),
        }

    async def _run_token_analysis(
        self, accounts: list[str]
    ) -> dict[str, Any]:
        from threatlens.analysis.token_abuse import TokenAbuseAnalyser

        analyser = TokenAbuseAnalyser()
        all_suspicious: list[str] = []
        combined_risk = 0.0
        for account in accounts[:5]:
            result = await analyser.analyse_user_consents(account)
            all_suspicious.extend(result.get("suspicious_consents", []))
            combined_risk = max(combined_risk, float(result.get("risk_score", 0)))
        return {
            "suspicious_consents": all_suspicious,
            "findings": all_suspicious[:10],
            "risk_score": round(combined_risk, 2),
        }

    async def _run_defender(
        self, accounts: list[str]
    ) -> list[dict[str, Any]]:
        from threatlens.azure.defender_client import DefenderClient

        client = DefenderClient()
        all_alerts: list[dict[str, Any]] = []
        for account in accounts[:5]:
            alerts = await client.get_user_alerts(account)
            all_alerts.extend(alerts)
        return all_alerts

    async def _render_verdict(self, report: InvestigationReport) -> dict[str, Any]:
        from threatlens.core.verdict_engine import VerdictEngine, VerdictInput

        engine = VerdictEngine()
        data = VerdictInput(
            incident_id=report.incident_id,
            triage_report=report.triage,
            identity_findings=report.identity_analysis,
            resource_findings=report.resource_analysis,
            privilege_findings=[report.privilege_analysis] if report.privilege_analysis else [],
            token_abuse_findings=[report.token_analysis] if report.token_analysis else [],
            defender_alerts=report.defender_alerts,
            llm_analysis=report.llm_analysis,
        )
        verdict = engine.render(data)
        return verdict.to_dict()

    async def _run_llm(self, report: InvestigationReport) -> str:
        from threatlens.reasoning.llm_engine import LLMEngine
        from threatlens.reasoning.prompt_templates import build_investigation_prompt

        engine = LLMEngine()
        prompt = build_investigation_prompt(report.to_dict())
        return await engine.complete(prompt)
