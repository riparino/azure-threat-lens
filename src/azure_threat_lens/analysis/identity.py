"""Identity abuse investigation – analyses Entra ID user risk signals."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from azure_threat_lens.integrations.azure.defender import DefenderClient
from azure_threat_lens.integrations.azure.graph import GraphClient
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.identity import IdentityInvestigationResult, SignInEvent, UserRoleAssignment

log = get_logger(__name__)

# Roles that are considered privileged
_PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Billing Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Hybrid Identity Administrator",
}


class IdentityInvestigator:
    """Investigates identity abuse signals for an Entra ID user."""

    def __init__(self) -> None:
        self._graph = GraphClient()
        self._defender = DefenderClient()

    async def investigate(
        self,
        identifier: str,
        *,
        lookback_days: int = 30,
    ) -> IdentityInvestigationResult:
        """Run a full identity investigation for a user (UPN, email, or object ID)."""
        log.info("identity.investigate", identifier=identifier, lookback_days=lookback_days)

        # Resolve user profile first to get the canonical object ID
        profile = await self._graph.get_user(identifier)
        if profile is None:
            log.error("identity.user_not_found", identifier=identifier)
            return IdentityInvestigationResult(
                user_id=identifier,
                user_principal_name=identifier,
                display_name="Unknown",
                key_findings=["User not found in Entra ID"],
            )

        user_id = profile.id
        upn = profile.user_principal_name

        # Parallel data gathering
        sign_ins, roles, mfa, defender_alerts = await asyncio.gather(
            self._graph.get_sign_in_logs(user_id, lookback_days=lookback_days),
            self._graph.get_directory_roles(user_id),
            self._graph.get_mfa_status(user_id),
            self._defender.get_user_alerts(upn),
        )

        # Analyse sign-in patterns
        analysis = self._analyse_sign_ins(sign_ins)

        # Determine privileged roles
        privileged = [r.role_name for r in roles if r.role_name in _PRIVILEGED_ROLES]

        # Compute risk score
        risk_score = self._compute_risk_score(
            sign_ins=sign_ins,
            analysis=analysis,
            privileged_roles=privileged,
            profile_enabled=profile.account_enabled,
            defender_alerts=defender_alerts,
            mfa_registered=mfa.is_mfa_registered,
        )

        findings = self._generate_findings(
            profile=profile,
            sign_ins=sign_ins,
            analysis=analysis,
            privileged_roles=privileged,
            mfa=mfa,
            defender_alerts=defender_alerts,
        )

        actions = self._recommend_actions(
            analysis=analysis,
            privileged_roles=privileged,
            mfa_registered=mfa.is_mfa_registered,
            risk_score=risk_score,
        )

        return IdentityInvestigationResult(
            user_id=user_id,
            user_principal_name=upn,
            display_name=profile.display_name,
            profile=profile,
            risk_score=risk_score,
            risk_level=_score_to_risk_level(risk_score),
            sign_in_events=sign_ins,
            impossible_travel_detected=analysis["impossible_travel"],
            anomalous_locations=analysis["anomalous_locations"],
            failed_mfa_count=analysis["failed_mfa"],
            successful_mfa_count=analysis["successful_mfa"],
            legacy_auth_sign_ins=analysis["legacy_auth"],
            high_risk_sign_ins=analysis["high_risk"],
            role_assignments=roles,
            privileged_roles=privileged,
            mfa_status=mfa,
            defender_alerts=defender_alerts,
            key_findings=findings,
            recommended_actions=actions,
        )

    # ── Sign-in analysis ───────────────────────────────────────────────────────

    @staticmethod
    def _analyse_sign_ins(sign_ins: list[SignInEvent]) -> dict[str, Any]:
        """Extract behavioural signals from sign-in logs."""
        analysis: dict[str, Any] = {
            "impossible_travel": False,
            "anomalous_locations": [],
            "failed_mfa": 0,
            "successful_mfa": 0,
            "legacy_auth": 0,
            "high_risk": 0,
            "countries": [],
            "unique_ips": set(),
        }
        if not sign_ins:
            return analysis

        # Track countries
        countries: list[str] = []
        timestamps: list[tuple[datetime, str]] = []

        legacy_clients = {
            "Exchange ActiveSync",
            "IMAP4",
            "POP3",
            "SMTP",
            "Authenticated SMTP",
            "AutoDiscover",
            "Other clients",
        }

        for signin in sign_ins:
            country = signin.location.get("countryOrRegion", "")
            if country:
                countries.append(country)
            if signin.ip_address:
                analysis["unique_ips"].add(signin.ip_address)
            if signin.created_date_time:
                timestamps.append((signin.created_date_time, country))
            if signin.risk_level_during_signin in ("high", "medium"):
                analysis["high_risk"] += 1
            if signin.client_app_used in legacy_clients:
                analysis["legacy_auth"] += 1
            mfa = signin.mfa_detail
            if mfa:
                if mfa.get("authMethod"):
                    analysis["successful_mfa"] += 1
                elif signin.status.get("errorCode") in (500121, 50074, 50076):
                    analysis["failed_mfa"] += 1

        # Impossible travel: two sign-ins from different countries within 1 hour
        if len(timestamps) >= 2:
            sorted_ts = sorted(timestamps, key=lambda x: x[0])
            for i in range(len(sorted_ts) - 1):
                t1, c1 = sorted_ts[i]
                t2, c2 = sorted_ts[i + 1]
                if c1 and c2 and c1 != c2:
                    diff = abs((t2 - t1).total_seconds())
                    if diff < 3600:  # 1 hour
                        analysis["impossible_travel"] = True
                        break

        country_counts = Counter(countries)
        # Anomalous = countries seen fewer than 10% of the time (but at least once)
        total = len(countries)
        analysis["anomalous_locations"] = [
            c for c, count in country_counts.items() if total > 0 and count / total < 0.1
        ]
        analysis["countries"] = list(country_counts.keys())
        analysis["unique_ips"] = list(analysis["unique_ips"])
        return analysis

    # ── Risk scoring ───────────────────────────────────────────────────────────

    @staticmethod
    def _compute_risk_score(
        sign_ins: list[SignInEvent],
        analysis: dict[str, Any],
        privileged_roles: list[str],
        profile_enabled: bool,
        defender_alerts: list[dict[str, Any]],
        mfa_registered: bool,
    ) -> float:
        score = 0.0

        if analysis["impossible_travel"]:
            score += 3.0
        if analysis["high_risk"] > 0:
            score += min(analysis["high_risk"] * 0.5, 3.0)
        if analysis["legacy_auth"] > 5:
            score += 1.5
        if analysis["failed_mfa"] > 3:
            score += 1.0
        if privileged_roles:
            score += min(len(privileged_roles) * 0.5, 2.0)
        if not mfa_registered:
            score += 1.5
        if defender_alerts:
            score += min(len(defender_alerts) * 0.3, 2.0)
        if not profile_enabled:
            # Disabled account signing in is very suspicious
            score += 3.0

        return round(min(score, 10.0), 2)

    # ── Findings & recommendations ────────────────────────────────────────────

    @staticmethod
    def _generate_findings(
        profile: Any,
        sign_ins: list[SignInEvent],
        analysis: dict[str, Any],
        privileged_roles: list[str],
        mfa: Any,
        defender_alerts: list[dict[str, Any]],
    ) -> list[str]:
        findings: list[str] = []
        if analysis["impossible_travel"]:
            findings.append("CRITICAL: Impossible travel detected – sign-ins from geographically distant locations within 1 hour")
        if analysis["high_risk"] > 0:
            findings.append(f"HIGH RISK: {analysis['high_risk']} sign-in(s) flagged as high/medium risk by Entra ID Identity Protection")
        if analysis["legacy_auth"] > 0:
            findings.append(f"Legacy authentication used in {analysis['legacy_auth']} sign-in(s) – bypasses MFA")
        if privileged_roles:
            findings.append(f"User holds {len(privileged_roles)} privileged role(s): {', '.join(privileged_roles)}")
        if not mfa.is_mfa_registered:
            findings.append("MFA not registered – account vulnerable to password-based attacks")
        if analysis["anomalous_locations"]:
            findings.append(f"Sign-ins from unusual countries: {', '.join(analysis['anomalous_locations'])}")
        if defender_alerts:
            findings.append(f"Defender XDR has {len(defender_alerts)} alert(s) associated with this user")
        if not profile.account_enabled:
            findings.append("WARNING: Account is disabled in Entra ID but sign-in activity was detected")
        if not findings:
            findings.append("No significant risk indicators detected in the analysis window")
        return findings

    @staticmethod
    def _recommend_actions(
        analysis: dict[str, Any],
        privileged_roles: list[str],
        mfa_registered: bool,
        risk_score: float,
    ) -> list[str]:
        actions: list[str] = []
        if analysis["impossible_travel"] or risk_score >= 7.0:
            actions.append("Immediately revoke all active sessions: Entra ID → Users → Revoke sessions")
        if not mfa_registered:
            actions.append("Enforce MFA registration via Conditional Access policy")
        if analysis["legacy_auth"] > 0:
            actions.append("Block legacy authentication protocols via Conditional Access")
        if privileged_roles and risk_score >= 5.0:
            actions.append("Review and potentially remove privileged role assignments pending investigation")
        actions.append("Require password reset on next sign-in")
        actions.append("Review OAuth app consents and delegated permissions for this user")
        actions.append("Check audit logs for any data exfiltration or admin actions in the last 30 days")
        return actions


def _score_to_risk_level(score: float) -> str:
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "none"
