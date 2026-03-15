"""Unit tests for the identity abuse analysis logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.analysis.identity_abuse import (
    analyse_sign_ins,
    compute_identity_risk,
    risk_score_to_level,
)
from threatlens.models.investigations import MFARegistration, SignInEvent


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


class TestSignInAnalysis:
    def test_impossible_travel_detected(self) -> None:
        now = datetime.now(timezone.utc)
        sign_ins = [
            _make_signin(country="US", created=now),
            _make_signin(country="RU", created=now - timedelta(minutes=30)),
        ]
        result = analyse_sign_ins(sign_ins)
        assert result["impossible_travel"] is True

    def test_no_impossible_travel_same_country(self) -> None:
        now = datetime.now(timezone.utc)
        sign_ins = [
            _make_signin(country="US", created=now),
            _make_signin(country="US", created=now - timedelta(hours=1)),
        ]
        result = analyse_sign_ins(sign_ins)
        assert result["impossible_travel"] is False

    def test_high_risk_sign_in_counted(self) -> None:
        sign_ins = [
            _make_signin(risk="high"),
            _make_signin(risk="medium"),
            _make_signin(risk="none"),
        ]
        result = analyse_sign_ins(sign_ins)
        assert result["high_risk"] == 2

    def test_legacy_auth_counted(self) -> None:
        sign_ins = [
            _make_signin(client_app="IMAP4"),
            _make_signin(client_app="POP3"),
            _make_signin(client_app="Browser"),
        ]
        result = analyse_sign_ins(sign_ins)
        assert result["legacy_auth"] == 2

    def test_empty_sign_ins(self) -> None:
        result = analyse_sign_ins([])
        assert result["impossible_travel"] is False
        assert result["high_risk"] == 0


class TestRiskScoring:
    def test_impossible_travel_adds_score(self) -> None:
        score = compute_identity_risk(
            analysis={"impossible_travel": True, "high_risk": 0, "legacy_auth": 0, "failed_mfa": 0},
            privileged_roles=[],
            account_enabled=True,
            mfa_registered=True,
            defender_alerts=[],
        )
        assert score >= 3.0

    def test_no_mfa_adds_score(self) -> None:
        no_mfa = compute_identity_risk(
            analysis={"impossible_travel": False, "high_risk": 0, "legacy_auth": 0, "failed_mfa": 0},
            privileged_roles=[],
            account_enabled=True,
            mfa_registered=False,
            defender_alerts=[],
        )
        with_mfa = compute_identity_risk(
            analysis={"impossible_travel": False, "high_risk": 0, "legacy_auth": 0, "failed_mfa": 0},
            privileged_roles=[],
            account_enabled=True,
            mfa_registered=True,
            defender_alerts=[],
        )
        assert no_mfa > with_mfa

    def test_score_bounded(self) -> None:
        score = compute_identity_risk(
            analysis={"impossible_travel": True, "high_risk": 20, "legacy_auth": 50, "failed_mfa": 20},
            privileged_roles=["Global Administrator", "Security Administrator"] * 5,
            account_enabled=False,
            mfa_registered=False,
            defender_alerts=[{}] * 20,
        )
        assert score <= 10.0

    def test_risk_level_labels(self) -> None:
        assert risk_score_to_level(9.0) == "critical"
        assert risk_score_to_level(6.5) == "high"
        assert risk_score_to_level(4.0) == "medium"
        assert risk_score_to_level(1.0) == "low"
        assert risk_score_to_level(0.0) == "none"


@pytest.mark.asyncio
class TestIdentityAbuseAnalyser:
    async def test_investigate_returns_investigation(self) -> None:
        from threatlens.models.investigations import UserProfile

        mock_profile = UserProfile(
            id="uid-001",
            displayName="Alice",
            userPrincipalName="alice@contoso.com",
        )

        mock_mfa = MFARegistration(
            is_mfa_registered=True, methods_registered=["microsoftAuthenticator"]
        )

        with (
            patch("threatlens.azure.graph_client.GraphClient") as MockGraph,
            patch("threatlens.azure.defender_client.DefenderClient") as MockDefender,
        ):
            mock_graph_inst = AsyncMock()
            mock_graph_inst.get_user.return_value = mock_profile
            mock_graph_inst.get_sign_in_logs.return_value = []
            mock_graph_inst.get_directory_roles.return_value = []
            mock_graph_inst.get_mfa_status.return_value = mock_mfa
            MockGraph.return_value = mock_graph_inst

            mock_defender_inst = AsyncMock()
            mock_defender_inst.get_user_alerts.return_value = []
            MockDefender.return_value = mock_defender_inst

            from threatlens.analysis.identity_abuse import IdentityAbuseAnalyser
            analyser = IdentityAbuseAnalyser()
            result = await analyser.investigate("alice@contoso.com")

        assert result.user_principal_name == "alice@contoso.com"
        assert 0.0 <= result.risk_score <= 10.0

    async def test_investigate_user_not_found(self) -> None:
        with (
            patch("threatlens.azure.graph_client.GraphClient") as MockGraph,
            patch("threatlens.azure.defender_client.DefenderClient"),
        ):
            mock_graph_inst = AsyncMock()
            mock_graph_inst.get_user.return_value = None
            MockGraph.return_value = mock_graph_inst

            from threatlens.analysis.identity_abuse import IdentityAbuseAnalyser
            analyser = IdentityAbuseAnalyser()
            result = await analyser.investigate("notfound@contoso.com")

        assert "User not found" in result.key_findings[0]
