"""Identity abuse analysis – detects compromise signals in Entra ID sign-in data."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from threatlens.models.investigations import IdentityInvestigation, MFARegistration, UserProfile
from threatlens.models.investigations import SignInEvent, UserRoleAssignment
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_PRIVILEGED_ROLES = {
    "Global Administrator", "Privileged Role Administrator", "Security Administrator",
    "Exchange Administrator", "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Hybrid Identity Administrator",
}

_LEGACY_CLIENTS = {
    "Exchange ActiveSync", "IMAP4", "POP3", "SMTP",
    "Authenticated SMTP", "AutoDiscover", "Other clients",
}


class IdentityAbuseAnalyser:
    """Analyses Entra ID sign-in logs and user attributes for abuse signals."""

    def __init__(self) -> None:
        from threatlens.azure.graph_client import GraphClient
        from threatlens.azure.sentinel_client import SentinelClient
        self._graph = GraphClient()

    async def investigate(
        self, identifier: str, *, lookback_days: int = 30
    ) -> IdentityInvestigation:
        """Full identity investigation for a user (UPN, email, or object ID)."""
        import asyncio
        from threatlens.azure.defender_client import DefenderClient

        log.info("identity_abuse.investigate", identifier=identifier)

        profile = await self._graph.get_user(identifier)
        if profile is None:
            return IdentityInvestigation(
                user_id=identifier,
                user_principal_name=identifier,
                key_findings=["User not found in Entra ID"],
            )

        defender = DefenderClient()
        sign_ins, roles, mfa, defender_alerts = await asyncio.gather(
            self._graph.get_sign_in_logs(profile.id, lookback_days=lookback_days),
            self._graph.get_directory_roles(profile.id),
            self._graph.get_mfa_status(profile.id),
            defender.get_user_alerts(profile.user_principal_name),
        )

        analysis = analyse_sign_ins(sign_ins)
        privileged = [r.role_name for r in roles if r.role_name in _PRIVILEGED_ROLES]
        risk_score = compute_identity_risk(
            analysis=analysis,
            privileged_roles=privileged,
            account_enabled=profile.account_enabled,
            mfa_registered=mfa.is_mfa_registered,
            defender_alerts=defender_alerts,
        )

        findings = generate_findings(profile, analysis, privileged, mfa, defender_alerts)
        actions = recommend_actions(analysis, privileged, mfa.is_mfa_registered, risk_score)

        return IdentityInvestigation(
            user_id=profile.id,
            user_principal_name=profile.user_principal_name,
            display_name=profile.display_name,
            profile=profile,
            risk_score=risk_score,
            risk_level=risk_score_to_level(risk_score),
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


# ── Pure analysis functions (stateless, testable) ─────────────────────────────

def analyse_sign_ins(sign_ins: list[SignInEvent]) -> dict[str, Any]:
    """Extract behavioural anomaly signals from a list of sign-in events."""
    result: dict[str, Any] = {
        "impossible_travel": False,
        "anomalous_locations": [],
        "failed_mfa": 0,
        "successful_mfa": 0,
        "legacy_auth": 0,
        "high_risk": 0,
        "unique_ips": [],
        "countries": [],
    }
    if not sign_ins:
        return result

    countries: list[str] = []
    unique_ips: set[str] = set()
    timestamps: list[tuple[datetime, str]] = []

    for signin in sign_ins:
        country = signin.location.get("countryOrRegion", "")
        if country:
            countries.append(country)
        if signin.ip_address:
            unique_ips.add(signin.ip_address)
        if signin.created_date_time:
            timestamps.append((signin.created_date_time, country))
        if signin.risk_level_during_signin in ("high", "medium"):
            result["high_risk"] += 1
        if signin.client_app_used in _LEGACY_CLIENTS:
            result["legacy_auth"] += 1
        mfa = signin.mfa_detail
        if mfa:
            if mfa.get("authMethod"):
                result["successful_mfa"] += 1
            elif signin.status.get("errorCode") in (500121, 50074, 50076):
                result["failed_mfa"] += 1

    # Impossible travel: different countries within 1 hour
    if len(timestamps) >= 2:
        sorted_ts = sorted(timestamps, key=lambda x: x[0])
        for i in range(len(sorted_ts) - 1):
            t1, c1 = sorted_ts[i]
            t2, c2 = sorted_ts[i + 1]
            if c1 and c2 and c1 != c2:
                if abs((t2 - t1).total_seconds()) < 3600:
                    result["impossible_travel"] = True
                    break

    total = len(countries)
    country_counts = Counter(countries)
    result["anomalous_locations"] = [
        c for c, n in country_counts.items() if total > 0 and n / total < 0.1
    ]
    result["countries"] = list(country_counts.keys())
    result["unique_ips"] = list(unique_ips)
    return result


def compute_identity_risk(
    analysis: dict[str, Any],
    privileged_roles: list[str],
    account_enabled: bool,
    mfa_registered: bool,
    defender_alerts: list[dict[str, Any]],
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
    if not account_enabled:
        score += 3.0
    return round(min(score, 10.0), 2)


def generate_findings(
    profile: UserProfile,
    analysis: dict[str, Any],
    privileged_roles: list[str],
    mfa: MFARegistration,
    defender_alerts: list[dict[str, Any]],
) -> list[str]:
    findings: list[str] = []
    if analysis["impossible_travel"]:
        findings.append("CRITICAL: Impossible travel – sign-ins from geographically distant locations within 1 hour")
    if analysis["high_risk"] > 0:
        findings.append(f"HIGH RISK: {analysis['high_risk']} sign-in(s) flagged by Entra ID Identity Protection")
    if analysis["legacy_auth"] > 0:
        findings.append(f"Legacy authentication used in {analysis['legacy_auth']} sign-in(s) – bypasses MFA")
    if privileged_roles:
        findings.append(f"User holds {len(privileged_roles)} privileged role(s): {', '.join(privileged_roles)}")
    if not mfa.is_mfa_registered:
        findings.append("MFA not registered – vulnerable to password-based attacks")
    if analysis["anomalous_locations"]:
        findings.append(f"Sign-ins from unusual countries: {', '.join(analysis['anomalous_locations'])}")
    if defender_alerts:
        findings.append(f"Defender XDR: {len(defender_alerts)} alert(s) associated with this user")
    if not profile.account_enabled:
        findings.append("WARNING: Account disabled but sign-in activity detected")
    return findings or ["No significant risk indicators detected"]


def recommend_actions(
    analysis: dict[str, Any],
    privileged_roles: list[str],
    mfa_registered: bool,
    risk_score: float,
) -> list[str]:
    actions: list[str] = []
    if analysis["impossible_travel"] or risk_score >= 7.0:
        actions.append("Revoke all active sessions immediately (Entra ID → Users → Revoke sessions)")
    if not mfa_registered:
        actions.append("Enforce MFA registration via Conditional Access policy")
    if analysis["legacy_auth"] > 0:
        actions.append("Block legacy authentication via Conditional Access")
    if privileged_roles and risk_score >= 5.0:
        actions.append("Review and potentially remove privileged roles pending investigation")
    actions.append("Require password reset on next sign-in")
    actions.append("Review OAuth app consents and delegated permissions")
    actions.append("Audit all admin actions in the last 30 days via Activity Log")
    return actions


def risk_score_to_level(score: float) -> str:
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "none"
