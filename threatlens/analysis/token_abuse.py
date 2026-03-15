"""Token abuse analysis – detects OAuth token theft and misuse patterns.

Covers: stolen refresh tokens, suspicious app consents, token replay from
anomalous locations, and service principal credential abuse.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from threatlens.utils.logging import get_logger

log = get_logger(__name__)

# Known attack patterns in Entra ID audit logs
_TOKEN_THEFT_OPERATIONS = {
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Consent to application",
    "Add delegation to application",
    "Update application",
    "Add service principal",
}

_SUSPICIOUS_APP_PERMISSIONS = {
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
}


class TokenAbuseAnalyser:
    """Detects OAuth token abuse and suspicious application consent patterns."""

    def __init__(self) -> None:
        from threatlens.azure.graph_client import GraphClient
        self._graph = GraphClient()

    async def analyse_user_consents(self, user_id: str) -> dict[str, Any]:
        """Analyse OAuth app consents granted by a user for suspicious permissions."""
        log.info("token_abuse.analyse_user_consents", user_id=user_id)
        try:
            data = await self._graph.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}/oauth2PermissionGrants"
            )
            grants: list[dict[str, Any]] = data.get("value", [])  # type: ignore[union-attr]
            return _evaluate_consents(grants)
        except Exception as exc:
            log.error("token_abuse.analyse_user_consents.failed", error=str(exc))
            return {"suspicious_consents": [], "risk_score": 0.0}

    async def analyse_service_principal(self, sp_id: str) -> dict[str, Any]:
        """Analyse a service principal for credential additions and permission scope."""
        log.info("token_abuse.analyse_service_principal", sp_id=sp_id)
        try:
            data = await self._graph.get(
                f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}"
            )
            return _evaluate_service_principal(data)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("token_abuse.analyse_service_principal.failed", error=str(exc))
            return {"findings": [], "risk_score": 0.0}


# ── Pure analysis functions ────────────────────────────────────────────────────

def _evaluate_consents(grants: list[dict[str, Any]]) -> dict[str, Any]:
    suspicious: list[str] = []
    risk_score = 0.0
    for grant in grants:
        scopes: str = grant.get("scope", "")
        client_id = grant.get("clientId", "")
        for perm in _SUSPICIOUS_APP_PERMISSIONS:
            if perm.lower() in scopes.lower():
                suspicious.append(f"App {client_id} granted: {perm}")
                risk_score = min(risk_score + 2.0, 10.0)
    return {"suspicious_consents": suspicious, "risk_score": round(risk_score, 2)}


def _evaluate_service_principal(data: dict[str, Any]) -> dict[str, Any]:
    findings: list[str] = []
    risk_score = 0.0
    # Multiple credentials = potential backdoor
    creds = data.get("passwordCredentials", []) + data.get("keyCredentials", [])
    if len(creds) > 2:
        findings.append(f"Unusual number of credentials: {len(creds)}")
        risk_score += min(len(creds) * 0.5, 3.0)
    # No owner (orphaned SP) is a risk indicator
    if not data.get("owners"):
        findings.append("Service principal has no owner (orphaned)")
        risk_score += 1.5
    return {"findings": findings, "risk_score": round(min(risk_score, 10.0), 2)}


def detect_token_replay(sign_ins: list[dict[str, Any]]) -> list[str]:
    """Detect token replay: same session ID used from multiple IPs/locations."""
    session_ips: dict[str, set[str]] = {}
    for signin in sign_ins:
        session_id = signin.get("correlationId") or signin.get("id", "")
        ip = signin.get("ipAddress", "")
        if session_id and ip:
            session_ips.setdefault(session_id, set()).add(ip)
    return [
        f"Session {sid} used from {len(ips)} different IPs – possible token replay"
        for sid, ips in session_ips.items()
        if len(ips) > 1
    ]
