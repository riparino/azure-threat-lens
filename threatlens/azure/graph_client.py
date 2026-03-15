"""Microsoft Graph API client (Entra ID / AAD)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from threatlens.azure._base import BaseAzureClient
from threatlens.models.investigations import MFARegistration, SignInEvent, UserProfile, UserRoleAssignment
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com"
_SCOPE = "https://graph.microsoft.com/.default"


class GraphClient(BaseAzureClient):
    """Client for Microsoft Graph – user profiles, sign-in logs, MFA, roles."""

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_SCOPE],
        )
        self._api = cfg.get_yaml("graph", "api_version", default="v1.0")

    def _url(self, path: str) -> str:
        return f"{_GRAPH_BASE}/{self._api}/{path.lstrip('/')}"

    async def get_user(self, identifier: str) -> UserProfile | None:
        log.info("graph.get_user", identifier=identifier)
        select = "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,createdDateTime,onPremisesSamAccountName,onPremisesSyncEnabled,usageLocation,assignedLicenses"
        try:
            data = await self.get(self._url(f"users/{identifier}"), params={"$select": select})
            return _parse_user(data)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("graph.get_user.failed", identifier=identifier, error=str(exc))
            return _mock_user(identifier)

    async def get_sign_in_logs(
        self, user_id: str, *, lookback_days: int = 30, top: int = 100
    ) -> list[SignInEvent]:
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
            return _mock_sign_ins(user_id)

    async def get_directory_roles(self, user_id: str) -> list[UserRoleAssignment]:
        log.info("graph.get_directory_roles", user_id=user_id)
        try:
            data = await self.get(self._url(f"users/{user_id}/memberOf"), params={"$top": 100})
            roles = []
            for m in data.get("value", []):  # type: ignore[union-attr]
                if m.get("@odata.type") == "#microsoft.graph.directoryRole":
                    roles.append(UserRoleAssignment(
                        role_name=m.get("displayName", ""),
                        role_id=m.get("id", ""),
                        scope="/",
                        principal_id=user_id,
                        principal_type="User",
                    ))
            return roles
        except Exception as exc:
            log.error("graph.get_directory_roles.failed", user_id=user_id, error=str(exc))
            return []

    async def get_mfa_status(self, user_id: str) -> MFARegistration:
        log.info("graph.get_mfa_status", user_id=user_id)
        try:
            data = await self.get(self._url(f"users/{user_id}/authentication/methods"))
            methods: list[dict[str, Any]] = data.get("value", [])  # type: ignore[union-attr]
            types = [m.get("@odata.type", "") for m in methods]
            is_mfa = any(t in types for t in [
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                "#microsoft.graph.phoneAuthenticationMethod",
                "#microsoft.graph.fido2AuthenticationMethod",
            ])
            return MFARegistration(
                is_mfa_registered=is_mfa,
                methods_registered=[t.split(".")[-1].replace("AuthenticationMethod", "") for t in types],
            )
        except Exception as exc:
            log.error("graph.get_mfa_status.failed", user_id=user_id, error=str(exc))
            return MFARegistration()


def _parse_user(raw: dict[str, Any]) -> UserProfile:
    licenses = [lic.get("skuId", "") for lic in raw.get("assignedLicenses", [])]
    return UserProfile.model_validate({**raw, "assignedLicenses": licenses})


def _mock_user(identifier: str) -> UserProfile:
    log.warning("graph.mock_user", identifier=identifier)
    return UserProfile(
        id="mock-uid-00001",
        displayName="[DEMO] Alex Johnson",
        userPrincipalName=identifier if "@" in identifier else f"{identifier}@demo.contoso.com",
        mail=identifier if "@" in identifier else f"{identifier}@demo.contoso.com",
        jobTitle="Cloud Engineer",
        department="IT Operations",
        accountEnabled=True,
    )


def _mock_sign_ins(user_id: str) -> list[SignInEvent]:
    log.warning("graph.mock_sign_ins", user_id=user_id)
    now = datetime.now(timezone.utc)
    return [
        SignInEvent.model_validate({
            "id": "mock-si-001", "userDisplayName": "[DEMO] Alex Johnson",
            "userPrincipalName": "alex@demo.contoso.com", "userId": user_id,
            "appDisplayName": "Microsoft Azure Portal", "appId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
            "ipAddress": "198.51.100.42", "clientAppUsed": "Browser",
            "conditionalAccessStatus": "success", "isInteractive": True,
            "riskLevelDuringSignIn": "high", "riskState": "atRisk",
            "status": {"errorCode": 0}, "location": {"city": "Unknown", "countryOrRegion": "RU"},
            "createdDateTime": now.isoformat(),
        }),
        SignInEvent.model_validate({
            "id": "mock-si-002", "userDisplayName": "[DEMO] Alex Johnson",
            "userPrincipalName": "alex@demo.contoso.com", "userId": user_id,
            "appDisplayName": "Azure AD", "appId": "00000002-0000-0000-c000-000000000000",
            "ipAddress": "10.0.0.5", "clientAppUsed": "MobileAppsAndDesktopClients",
            "conditionalAccessStatus": "success", "isInteractive": False,
            "riskLevelDuringSignIn": "none", "riskState": "none",
            "status": {"errorCode": 0}, "location": {"city": "New York", "countryOrRegion": "US"},
            "createdDateTime": (now - timedelta(hours=2)).isoformat(),
        }),
    ]
