"""Unit tests for Pydantic data models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from threatlens.models.entities import EntityKind, ResolvedEntity, ThreatIntelHit, RawEntity
from threatlens.models.investigations import (
    IdentityInvestigation,
    MFARegistration,
    UserProfile,
)
from threatlens.models.incidents import Alert, Incident, IncidentStatus, Severity


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

    def test_alert_defaults(self) -> None:
        alert = Alert.model_validate({"systemAlertId": "a-001"})
        assert alert.alert_id == "a-001"
        assert alert.severity == Severity.INFORMATIONAL


class TestEntityModels:
    def test_threat_intel_hit(self) -> None:
        hit = ThreatIntelHit(provider="virustotal", malicious=True, score=8.5)
        assert hit.malicious is True
        assert hit.score == 8.5

    def test_resolved_entity_defaults(self) -> None:
        entity = ResolvedEntity(
            entity_kind=EntityKind.IP,
            identifier="8.8.8.8",
            risk_score=2.0,
            risk_label="Low",
        )
        assert entity.entity_kind == EntityKind.IP
        assert 0.0 <= entity.risk_score <= 10.0

    def test_resolved_entity_risk_score_bounds(self) -> None:
        with pytest.raises(Exception):
            ResolvedEntity(
                entity_kind=EntityKind.IP,
                identifier="1.2.3.4",
                risk_score=11.0,  # out of range
                risk_label="Critical",
            )

    def test_raw_entity_primary_identifier_upn(self) -> None:
        entity = RawEntity.model_validate({
            "entityType": "Account",
            "friendlyName": "alice",
            "properties": {
                "userPrincipalName": "alice@contoso.com",
                "accountName": "alice",
            },
        })
        assert entity.primary_identifier() == "alice@contoso.com"

    def test_raw_entity_primary_identifier_ip(self) -> None:
        entity = RawEntity.model_validate({
            "entityType": "Ip",
            "friendlyName": "1.2.3.4",
            "properties": {"address": "1.2.3.4"},
        })
        assert entity.primary_identifier() == "1.2.3.4"

    def test_raw_entity_falls_back_to_friendly_name(self) -> None:
        entity = RawEntity.model_validate({
            "entityType": "Unknown",
            "friendlyName": "mystery",
            "properties": {},
        })
        assert entity.primary_identifier() == "mystery"


class TestIdentityModels:
    def test_user_profile_defaults(self) -> None:
        profile = UserProfile(
            id="user-001",
            displayName="Alice",
            userPrincipalName="alice@contoso.com",
        )
        assert profile.account_enabled is True
        assert profile.display_name == "Alice"

    def test_mfa_registration(self) -> None:
        mfa = MFARegistration(
            is_mfa_registered=True,
            methods_registered=["microsoftAuthenticator"],
        )
        assert mfa.is_mfa_registered is True
        assert "microsoftAuthenticator" in mfa.methods_registered

    def test_identity_investigation(self) -> None:
        result = IdentityInvestigation(
            user_id="uid-001",
            user_principal_name="bob@contoso.com",
            risk_score=7.5,
            risk_level="high",
        )
        assert result.risk_score == 7.5
        assert result.impossible_travel_detected is False
