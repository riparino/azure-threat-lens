"""Unit tests for the identity investigator analysis logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from azure_threat_lens.analysis.identity import _score_to_risk_level
from azure_threat_lens.models.identity import MFARegistration, SignInEvent


def _make_signin(
    country: str = "US",
    risk: str = "none",
    created: datetime | None = None,
    client_app: str = "Browser",
) -> SignInEvent:
    return SignInEvent.model_validate(
        {
            "id": "si-001",
            "userDisplayName": "Test User",
            "userPrincipalName": "test@contoso.com",
            "userId": "uid-001",
            "appDisplayName": "Azure Portal",
            "appId": "app-001",
            "ipAddress": "8.8.8.8",
            "clientAppUsed": client_app,
            "conditionalAccessStatus": "success",
            "isInteractive": True,
            "riskLevelDuringSignIn": risk,
            "riskState": "none",
            "status": {"errorCode": 0},
            "location": {"countryOrRegion": country, "city": "SomeCity"},
            "createdDateTime": (created or datetime.now(timezone.utc)).isoformat(),
        }
    )


@pytest.fixture
def investigator():
    """Create an IdentityInvestigator with Azure clients mocked out."""
    with (
        patch("azure_threat_lens.analysis.identity.GraphClient") as mock_graph,
        patch("azure_threat_lens.analysis.identity.DefenderClient") as mock_defender,
    ):
        mock_graph.return_value = MagicMock()
        mock_defender.return_value = MagicMock()
        from azure_threat_lens.analysis.identity import IdentityInvestigator
        return IdentityInvestigator()


class TestSignInAnalysis:
    def test_impossible_travel_detected(self, investigator) -> None:
        now = datetime.now(timezone.utc)
        sign_ins = [
            _make_signin(country="US", created=now),
            _make_signin(country="RU", created=now - timedelta(minutes=30)),
        ]
        result = investigator._analyse_sign_ins(sign_ins)
        assert result["impossible_travel"] is True

    def test_no_impossible_travel_same_country(self, investigator) -> None:
        now = datetime.now(timezone.utc)
        sign_ins = [
            _make_signin(country="US", created=now),
            _make_signin(country="US", created=now - timedelta(hours=1)),
        ]
        result = investigator._analyse_sign_ins(sign_ins)
        assert result["impossible_travel"] is False

    def test_high_risk_sign_in_counted(self, investigator) -> None:
        sign_ins = [
            _make_signin(risk="high"),
            _make_signin(risk="medium"),
            _make_signin(risk="none"),
        ]
        result = investigator._analyse_sign_ins(sign_ins)
        assert result["high_risk"] == 2

    def test_legacy_auth_counted(self, investigator) -> None:
        sign_ins = [
            _make_signin(client_app="IMAP4"),
            _make_signin(client_app="POP3"),
            _make_signin(client_app="Browser"),
        ]
        result = investigator._analyse_sign_ins(sign_ins)
        assert result["legacy_auth"] == 2

    def test_empty_sign_ins(self, investigator) -> None:
        result = investigator._analyse_sign_ins([])
        assert result["impossible_travel"] is False
        assert result["high_risk"] == 0


class TestRiskScoring:
    def test_impossible_travel_adds_score(self, investigator) -> None:
        score = investigator._compute_risk_score(
            sign_ins=[],
            analysis={"impossible_travel": True, "high_risk": 0, "legacy_auth": 0, "failed_mfa": 0},
            privileged_roles=[],
            profile_enabled=True,
            defender_alerts=[],
            mfa_registered=True,
        )
        assert score >= 3.0

    def test_no_mfa_adds_score(self, investigator) -> None:
        no_mfa = investigator._compute_risk_score(
            sign_ins=[],
            analysis={"impossible_travel": False, "high_risk": 0, "legacy_auth": 0, "failed_mfa": 0},
            privileged_roles=[],
            profile_enabled=True,
            defender_alerts=[],
            mfa_registered=False,
        )
        with_mfa = investigator._compute_risk_score(
            sign_ins=[],
            analysis={"impossible_travel": False, "high_risk": 0, "legacy_auth": 0, "failed_mfa": 0},
            privileged_roles=[],
            profile_enabled=True,
            defender_alerts=[],
            mfa_registered=True,
        )
        assert no_mfa > with_mfa

    def test_score_bounded(self, investigator) -> None:
        score = investigator._compute_risk_score(
            sign_ins=[],
            analysis={"impossible_travel": True, "high_risk": 20, "legacy_auth": 50, "failed_mfa": 20},
            privileged_roles=["Global Administrator", "Security Administrator"] * 5,
            profile_enabled=False,
            defender_alerts=[{}] * 20,
            mfa_registered=False,
        )
        assert score <= 10.0

    def test_risk_level_labels(self) -> None:
        assert _score_to_risk_level(9.0) == "critical"
        assert _score_to_risk_level(6.5) == "high"
        assert _score_to_risk_level(4.0) == "medium"
        assert _score_to_risk_level(1.0) == "low"
        assert _score_to_risk_level(0.0) == "none"
