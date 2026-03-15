"""Unit tests for Pydantic data models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from azure_threat_lens.models.entity import EntityKind, EntityResolutionResult, ThreatIntelHit
from azure_threat_lens.models.identity import IdentityInvestigationResult, MFARegistration, UserProfile
from azure_threat_lens.models.incident import Alert, Incident, IncidentStatus, Severity, TriageResult


class TestIncidentModels:
    def test_incident_defaults(self) -> None:
        inc = Incident.model_validate({"incidentId": "test-001"})
        assert inc.incident_id == "test-001"
        assert inc.severity == Severity.INFORMATIONAL
        assert inc.status == IncidentStatus.NEW
        assert inc.tactics == []

    def test_incident_full(self) -> None:
        inc = Incident.model_validate(
            {
                "incidentId": "inc-abc",
                "incidentNumber": 42,
                "title": "Suspicious PowerShell",
                "severity": "High",
                "status": "Active",
                "tactics": ["Execution"],
                "techniques": ["T1059.001"],
                "createdTimeUtc": "2024-01-15T10:00:00Z",
            }
        )
        assert inc.incident_number == 42
        assert inc.severity == Severity.HIGH
        assert inc.status == IncidentStatus.ACTIVE
        assert "Execution" in inc.tactics

    def test_triage_result_score_bounds(self) -> None:
        result = TriageResult(
            incident_id="x",
            incident_number=1,
            title="Test",
            severity=Severity.HIGH,
            priority_score=9.5,
            priority_label="Critical",
            summary="Test incident",
        )
        assert 0.0 <= result.priority_score <= 10.0


class TestEntityModels:
    def test_threat_intel_hit(self) -> None:
        hit = ThreatIntelHit(provider="virustotal", malicious=True, score=8.5)
        assert hit.malicious is True
        assert hit.score == 8.5

    def test_entity_resolution_result(self) -> None:
        result = EntityResolutionResult(
            entity_kind=EntityKind.IP,
            identifier="8.8.8.8",
            risk_score=2.0,
            risk_label="Low",
        )
        assert result.entity_kind == EntityKind.IP
        assert 0.0 <= result.risk_score <= 10.0

    def test_entity_risk_score_bounds(self) -> None:
        with pytest.raises(Exception):
            EntityResolutionResult(
                entity_kind=EntityKind.IP,
                identifier="1.2.3.4",
                risk_score=11.0,  # out of range
                risk_label="Critical",
            )


class TestIdentityModels:
    def test_user_profile_defaults(self) -> None:
        profile = UserProfile(id="user-001", displayName="Alice", userPrincipalName="alice@contoso.com")
        assert profile.account_enabled is True
        assert profile.display_name == "Alice"

    def test_mfa_registration(self) -> None:
        mfa = MFARegistration(is_mfa_registered=True, methods_registered=["microsoftAuthenticator"])
        assert mfa.is_mfa_registered is True
        assert "microsoftAuthenticator" in mfa.methods_registered

    def test_identity_investigation_result(self) -> None:
        result = IdentityInvestigationResult(
            user_id="uid-001",
            user_principal_name="bob@contoso.com",
            risk_score=7.5,
            risk_level="high",
        )
        assert result.risk_score == 7.5
        assert result.impossible_travel_detected is False
