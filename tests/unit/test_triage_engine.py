"""Unit tests for the TriageEngine module."""

from __future__ import annotations

import json

import pytest

from threatlens.core.triage_engine import TriageEngine, TriageInput


def _sample_input(
    severity: str = "High",
    tactics: list[str] | None = None,
    entities: list[dict] | None = None,
    alerts: list[dict] | None = None,
) -> TriageInput:
    return TriageInput(
        incident={
            "incidentId": "test-engine-001",
            "incidentNumber": 42,
            "title": "Suspicious sign-in from anonymous IP and credential spray",
            "description": (
                "User signed in from a known anonymous proxy; "
                "multiple failed MFA attempts detected."
            ),
            "severity": severity,
            "status": "New",
            "tactics": tactics or ["InitialAccess", "CredentialAccess"],
            "techniques": ["T1078", "T1110"],
        },
        alerts=alerts or [
            {
                "systemAlertId": "alert-001",
                "alertDisplayName": "Sign-in from anonymous IP",
                "severity": "High",
                "description": "User alice@contoso.com signed in from anonymous proxy 1.2.3.4",
                "tactics": ["InitialAccess"],
                "techniques": ["T1078"],
            },
            {
                "systemAlertId": "alert-002",
                "alertDisplayName": "MFA brute-force attempt",
                "severity": "Medium",
                "description": "15 failed MFA attempts for alice@contoso.com",
                "tactics": ["CredentialAccess"],
                "techniques": ["T1110"],
            },
        ],
        entities=entities or [
            {
                "entityType": "Account",
                "friendlyName": "alice@contoso.com",
                "properties": {
                    "userPrincipalName": "alice@contoso.com",
                    "accountName": "alice",
                },
            },
            {
                "entityType": "Ip",
                "friendlyName": "1.2.3.4",
                "properties": {"address": "1.2.3.4"},
            },
        ],
        time_range={
            "start": "2024-01-15T00:00:00Z",
            "end": "2024-01-15T06:00:00Z",
        },
    )


@pytest.mark.asyncio
class TestTriageEngine:
    async def test_basic_output_structure(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())

        assert result.incident_id == "test-engine-001"
        assert result.summary != ""
        assert result.risk_level in ("critical", "high", "medium", "low")
        assert isinstance(result.key_entities, list)
        assert isinstance(result.attack_hypotheses, list)
        assert isinstance(result.recommended_queries, list)
        assert isinstance(result.investigation_steps, list)
        assert result.confidence in ("high", "medium", "low")

    async def test_entity_extraction(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())

        kinds = {e.kind for e in result.key_entities}
        assert "Account" in kinds
        assert "Ip" in kinds

        account = next(e for e in result.key_entities if e.kind == "Account")
        assert "alice@contoso.com" in account.identifier

    async def test_attack_hypotheses_detected(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        assert len(result.attack_hypotheses) > 0

    async def test_mitre_tactics_extracted(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        assert "InitialAccess" in result.mitre_tactics
        assert "CredentialAccess" in result.mitre_tactics

    async def test_queries_generated_for_account(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        query_names = [q.name for q in result.recommended_queries]
        assert any("sign" in n.lower() or "alice" in n.lower() for n in query_names)

    async def test_queries_generated_for_ip(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        assert any("ip" in q.name.lower() or "1.2.3" in q.kql for q in result.recommended_queries)

    async def test_kql_queries_are_non_empty(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        for q in result.recommended_queries:
            assert q.kql.strip() != "", f"Empty KQL for query: {q.name}"
            assert q.name != ""
            assert q.description != ""

    async def test_investigation_steps_non_empty(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        assert len(result.investigation_steps) >= 3

    async def test_high_severity_is_high_risk(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input(severity="High"))
        assert result.risk_level in ("critical", "high")

    async def test_informational_severity_low_risk(self) -> None:
        engine = TriageEngine()
        result = await engine.run(
            TriageInput(
                incident={
                    "incidentId": "info-001",
                    "incidentNumber": 1,
                    "title": "Informational scan",
                    "severity": "Informational",
                    "tactics": [],
                    "techniques": [],
                },
                alerts=[],
                entities=[],
            )
        )
        assert result.risk_level in ("low", "medium", "informational")

    async def test_json_serialisable(self) -> None:
        engine = TriageEngine()
        result = await engine.run(_sample_input())
        serialised = result.model_dump_json()
        parsed = json.loads(serialised)
        assert parsed["risk_level"] == result.risk_level

    async def test_confidence_scales_with_data(self) -> None:
        engine = TriageEngine()
        rich_result = await engine.run(_sample_input())
        sparse_result = await engine.run(
            TriageInput(
                incident={
                    "incidentId": "sparse",
                    "incidentNumber": 2,
                    "title": "x",
                    "severity": "Low",
                },
                alerts=[],
                entities=[],
            )
        )
        confidence_map = {"high": 3, "medium": 2, "low": 1}
        assert confidence_map[rich_result.confidence] >= confidence_map[sparse_result.confidence]
