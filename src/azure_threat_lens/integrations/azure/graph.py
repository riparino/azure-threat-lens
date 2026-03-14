"""Microsoft Graph / Entra ID integration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.azure.base import BaseAzureClient
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.identity import (
    MFARegistration,
    SignInEvent,
    UserProfile,
    UserRoleAssignment,
)

log = get_logger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class GraphClient(BaseAzureClient):
    """Client for Microsoft Graph API (Entra ID / AAD)."""

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_GRAPH_SCOPE],
            timeout=cfg.get_yaml("azure", "request_timeout", default=30),
        )
        self._api_ver = cfg.get_yaml("graph", "api_version", default="v1.0")

    def _url(self, path: str) -> str:
        return f"{_GRAPH_BASE}/{self._api_ver}/{path.lstrip('/')}"

    # ── User profiles ──────────────────────────────────────────────────────────

    async def get_user(self, identifier: str) -> UserProfile | None:
        """Fetch a user by UPN, email, or object ID."""
        log.info("graph.get_user", identifier=identifier)
        try:
            select = "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,createdDateTime,onPremisesSamAccountName,onPremisesSyncEnabled,usageLocation,assignedLicenses"
            data = await self.get(self._url(f"users/{identifier}"), params={"$select": select})
            return self._parse_user(data)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("graph.get_user.failed", identifier=identifier, error=str(exc))
            return self._mock_user(identifier)

    async def list_users(self, *, search: str = "", top: int = 10) -> list[UserProfile]:
        """Search users by display name or UPN."""
        params: dict[str, Any] = {"$top": top, "$select": "id,displayName,userPrincipalName,mail,accountEnabled"}
        if search:
            params["$filter"] = f"startswith(displayName,'{search}') or startswith(userPrincipalName,'{search}')"
        try:
            data = await self.get(self._url("users"), params=params)
            return [self._parse_user(u) for u in data.get("value", [])]  # type: ignore[union-attr]
        except Exception as exc:
            log.error("graph.list_users.failed", error=str(exc))
            return []

    # ── Sign-in logs ───────────────────────────────────────────────────────────

    async def get_sign_in_logs(
        self,
        user_id: str,
        *,
        lookback_days: int = 30,
        top: int = 100,
    ) -> list[SignInEvent]:
        """Fetch Entra ID sign-in logs for a user."""
        since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        params: dict[str, Any] = {
            "$filter": f"userId eq '{user_id}' and createdDateTime ge {since}",
            "$orderby": "createdDateTime desc",
            "$top": top,
        }
        log.info("graph.get_sign_in_logs", user_id=user_id, lookback_days=lookback_days)
        try:
            data = await self.get(self._url("auditLogs/signIns"), params=params)
            return [SignInEvent.model_validate(e) for e in data.get("value", [])]  # type: ignore[union-attr]
        except Exception as exc:
            log.error("graph.get_sign_in_logs.failed", user_id=user_id, error=str(exc))
            return self._mock_sign_ins(user_id)

    # ── Role assignments ───────────────────────────────────────────────────────

    async def get_directory_roles(self, user_id: str) -> list[UserRoleAssignment]:
        """Get Entra ID directory roles assigned to a user."""
        log.info("graph.get_directory_roles", user_id=user_id)
        try:
            data = await self.get(self._url(f"users/{user_id}/memberOf"), params={"$top": 100})
            roles = []
            for member in data.get("value", []):  # type: ignore[union-attr]
                if member.get("@odata.type") == "#microsoft.graph.directoryRole":
                    roles.append(
                        UserRoleAssignment(
                            role_name=member.get("displayName", ""),
                            role_id=member.get("id", ""),
                            scope="/",
                            assignment_type="Direct",
                            principal_id=user_id,
                            principal_type="User",
                        )
                    )
            return roles
        except Exception as exc:
            log.error("graph.get_directory_roles.failed", user_id=user_id, error=str(exc))
            return []

    # ── MFA status ────────────────────────────────────────────────────────────

    async def get_mfa_status(self, user_id: str) -> MFARegistration:
        """Get authentication methods registered for a user."""
        log.info("graph.get_mfa_status", user_id=user_id)
        try:
            data = await self.get(self._url(f"users/{user_id}/authentication/methods"))
            methods: list[dict[str, Any]] = data.get("value", [])  # type: ignore[union-attr]
            method_types = [m.get("@odata.type", "") for m in methods]
            is_mfa = any(
                t in method_types
                for t in [
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                    "#microsoft.graph.phoneAuthenticationMethod",
                    "#microsoft.graph.fido2AuthenticationMethod",
                ]
            )
            return MFARegistration(
                is_mfa_registered=is_mfa,
                methods_registered=[t.split(".")[-1].replace("AuthenticationMethod", "") for t in method_types],
            )
        except Exception as exc:
            log.error("graph.get_mfa_status.failed", user_id=user_id, error=str(exc))
            return MFARegistration()

    # ── Parsers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_user(raw: dict[str, Any]) -> UserProfile:
        licenses = [lic.get("skuId", "") for lic in raw.get("assignedLicenses", [])]
        return UserProfile.model_validate({**raw, "assignedLicenses": licenses})

    # ── Mock data ──────────────────────────────────────────────────────────────

    @staticmethod
    def _mock_user(identifier: str) -> UserProfile:
        log.warning("graph.using_mock_user", identifier=identifier)
        return UserProfile(
            id="mock-user-id-00000001",
            displayName="[DEMO] Alex Johnson",
            userPrincipalName=identifier if "@" in identifier else f"{identifier}@demo.contoso.com",
            mail=f"{identifier}@demo.contoso.com" if "@" not in identifier else identifier,
            jobTitle="Cloud Engineer",
            department="IT Operations",
            accountEnabled=True,
        )

    @staticmethod
    def _mock_sign_ins(user_id: str) -> list[SignInEvent]:
        log.warning("graph.using_mock_sign_ins", user_id=user_id)
        now = datetime.now(timezone.utc)
        return [
            SignInEvent.model_validate(
                {
                    "id": "mock-signin-001",
                    "userDisplayName": "[DEMO] Alex Johnson",
                    "userPrincipalName": "alex.johnson@demo.contoso.com",
                    "userId": user_id,
                    "appDisplayName": "Microsoft Azure Portal",
                    "appId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
                    "ipAddress": "198.51.100.42",
                    "clientAppUsed": "Browser",
                    "conditionalAccessStatus": "success",
                    "isInteractive": True,
                    "riskLevelDuringSignIn": "high",
                    "riskState": "atRisk",
                    "status": {"errorCode": 0, "failureReason": ""},
                    "location": {"city": "Unknown City", "countryOrRegion": "RU", "state": ""},
                    "createdDateTime": now.isoformat(),
                }
            ),
            SignInEvent.model_validate(
                {
                    "id": "mock-signin-002",
                    "userDisplayName": "[DEMO] Alex Johnson",
                    "userPrincipalName": "alex.johnson@demo.contoso.com",
                    "userId": user_id,
                    "appDisplayName": "Azure Active Directory",
                    "appId": "00000002-0000-0000-c000-000000000000",
                    "ipAddress": "10.0.0.5",
                    "clientAppUsed": "MobileAppsAndDesktopClients",
                    "conditionalAccessStatus": "success",
                    "isInteractive": False,
                    "riskLevelDuringSignIn": "none",
                    "riskState": "none",
                    "status": {"errorCode": 0, "failureReason": ""},
                    "location": {"city": "New York", "countryOrRegion": "US", "state": "New York"},
                    "createdDateTime": (now - timedelta(hours=2)).isoformat(),
                }
            ),
        ]
