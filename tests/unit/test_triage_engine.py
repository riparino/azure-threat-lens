"""Unit tests for the TriageEngine module."""

from __future__ import annotations

import pytest

from azure_threat_lens.analysis.triage_engine import TriageEngine, TriageEngineInput


def _sample_input(
    severity: str = "High",
    tactics: list[str] | None = None,
    entities: list[dict] | None = None,
    alerts: list[dict] | None = None,
) -> TriageEngineInput:
    return TriageEngineInput(
        incident={
            "incidentId": "test-engine-001",
            "incidentNumber": 42,
            "title": "Suspicious sign-in from anonymous IP and credential spray",
            "description": "User signed in from a known anonymous proxy; multiple failed MFA attempts detected.",
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
                "description": "User alice@contoso.com signed in from anonymous proxy 198.51.100.42",
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
                "properties": {"userPrincipalName": "alice@contoso.com", "accountName": "alice"},
            },
            {
                "entityType": "Ip",
                "friendlyName": "198.51.100.42",
                "properties": {"address": "198.51.100.42"},
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
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        assert result.summary != ""
        assert result.risk_level in ("critical", "high", "medium", "low", "informational")
        assert isinstance(result.entities, list)
        assert isinstance(result.recommended_queries, list)
        assert isinstance(result.investigation_steps, list)
        assert result.confidence in ("high", "medium", "low")
        assert result.engine_mode == "deterministic"

    async def test_entity_extraction(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        kinds = {e.kind for e in result.entities}
        assert "Account" in kinds
        assert "Ip" in kinds

        account = next(e for e in result.entities if e.kind == "Account")
        assert "alice@contoso.com" in account.identifier

    async def test_attack_patterns_detected(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        # The incident title contains "credential spray" → CredentialAccess
        # and "anonymous IP" → InitialAccess
        assert len(result.attack_patterns) > 0

    async def test_mitre_tactics_extracted(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        assert "InitialAccess" in result.mitre_tactics
        assert "CredentialAccess" in result.mitre_tactics

    async def test_queries_generated_for_account(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        query_names = [q.name for q in result.recommended_queries]
        # Should have sign-in query for alice@contoso.com
        assert any("sign_in" in n or "alice" in n for n in query_names)

    async def test_queries_generated_for_ip(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        # Should have an IP activity query for 198.51.100.42
        assert any("ip_activity" in q.name or "198" in q.name for q in result.recommended_queries)

    async def test_kql_queries_are_non_empty(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        for q in result.recommended_queries:
            assert q.kql.strip() != "", f"Empty KQL for query: {q.name}"
            assert q.name != ""
            assert q.description != ""

    async def test_investigation_steps_ordered(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())

        # First step should be about evidence preservation
        assert len(result.investigation_steps) >= 3
        assert "evidence" in result.investigation_steps[0].lower() or "preserve" in result.investigation_steps[0].lower()

    async def test_high_severity_is_high_risk(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input(severity="High"))
        assert result.risk_level in ("critical", "high")

    async def test_informational_severity_low_risk(self) -> None:
        engine = TriageEngine(use_llm=False)
        result = await engine.run(
            TriageEngineInput(
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
        import json
        engine = TriageEngine(use_llm=False)
        result = await engine.run(_sample_input())
        # Should not raise
        serialised = result.model_dump_json()
        parsed = json.loads(serialised)
        assert parsed["risk_level"] == result.risk_level

    async def test_confidence_scales_with_data(self) -> None:
        engine = TriageEngine(use_llm=False)

        # Rich input
        rich_result = await engine.run(_sample_input())

        # Sparse input
        sparse_result = await engine.run(
            TriageEngineInput(
                incident={"incidentId": "sparse", "incidentNumber": 2, "title": "x", "severity": "Low"},
                alerts=[],
                entities=[],
            )
        )
        confidence_map = {"high": 3, "medium": 2, "low": 1}
        assert confidence_map[rich_result.confidence] >= confidence_map[sparse_result.confidence]
