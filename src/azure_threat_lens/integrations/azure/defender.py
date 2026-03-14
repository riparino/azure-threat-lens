"""Microsoft Defender XDR / Defender for Endpoint integration."""

from __future__ import annotations

from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.azure.base import BaseAzureClient
from azure_threat_lens.logging import get_logger

log = get_logger(__name__)

_DEFENDER_BASE = "https://api.security.microsoft.com"
_DEFENDER_SCOPE = "https://api.security.microsoft.com/.default"


class DefenderClient(BaseAzureClient):
    """Client for Microsoft Defender XDR / Defender for Endpoint APIs."""

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.defender.tenant_id or cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_DEFENDER_SCOPE],
            timeout=cfg.get_yaml("azure", "request_timeout", default=30),
        )
        self._enabled = cfg.defender.enabled
        self._api_ver = cfg.defender.api_version

    def _url(self, path: str) -> str:
        return f"{_DEFENDER_BASE}/api/{path.lstrip('/')}"

    async def _check_enabled(self) -> bool:
        if not self._enabled:
            log.info("defender.disabled", hint="Set ATL_DEFENDER_ENABLED=true to enable")
            return False
        return True

    # ── Alerts ────────────────────────────────────────────────────────────────

    async def get_alerts_for_machine(self, machine_id: str, *, top: int = 20) -> list[dict[str, Any]]:
        """Fetch Defender alerts for a specific machine."""
        if not await self._check_enabled():
            return self._mock_alerts(machine_id)
        try:
            data = await self.get(
                self._url(f"machines/{machine_id}/alerts"),
                params={"$top": top, "$orderby": "alertCreationTime desc"},
            )
            return data.get("value", [])  # type: ignore[return-value,union-attr]
        except Exception as exc:
            log.error("defender.get_alerts_for_machine.failed", machine_id=machine_id, error=str(exc))
            return []

    async def get_machine_info(self, machine_id: str) -> dict[str, Any] | None:
        """Get Defender machine details including risk score and health status."""
        if not await self._check_enabled():
            return self._mock_machine(machine_id)
        try:
            data = await self.get(self._url(f"machines/{machine_id}"))
            return data  # type: ignore[return-value]
        except Exception as exc:
            log.error("defender.get_machine_info.failed", machine_id=machine_id, error=str(exc))
            return None

    async def run_advanced_hunting(self, query: str) -> list[dict[str, Any]]:
        """Execute a KQL query via Defender XDR Advanced Hunting."""
        if not await self._check_enabled():
            log.warning("defender.advanced_hunting.skipped", reason="Defender integration disabled")
            return []
        try:
            data = await self.post(
                self._url("advancedqueries/run"),
                json={"Query": query},
            )
            return data.get("Results", [])  # type: ignore[return-value,union-attr]
        except Exception as exc:
            log.error("defender.advanced_hunting.failed", error=str(exc))
            return []

    async def get_user_alerts(self, user_principal_name: str, *, top: int = 20) -> list[dict[str, Any]]:
        """Fetch Defender alerts related to a specific user."""
        if not await self._check_enabled():
            return self._mock_user_alerts(user_principal_name)
        query = f"""
        AlertInfo
        | where AccountUpn =~ '{user_principal_name}'
        | join kind=inner AlertEvidence on AlertId
        | top {top} by Timestamp desc
        | project AlertId, Title, Severity, Category, AccountUpn, Timestamp, AttackTechniques
        """
        return await self.run_advanced_hunting(query)

    # ── Mock data ──────────────────────────────────────────────────────────────

    @staticmethod
    def _mock_alerts(machine_id: str) -> list[dict[str, Any]]:
        return [
            {
                "id": "mock-alert-mde-001",
                "title": "[DEMO] Suspicious PowerShell execution",
                "severity": "High",
                "status": "New",
                "machineId": machine_id,
                "category": "Execution",
                "mitreTechniques": ["T1059.001"],
            }
        ]

    @staticmethod
    def _mock_machine(machine_id: str) -> dict[str, Any]:
        return {
            "id": machine_id,
            "computerDnsName": "demo-workstation-01.contoso.com",
            "osPlatform": "Windows10",
            "riskScore": "High",
            "healthStatus": "Active",
            "lastSeen": "2024-01-15T10:30:00Z",
        }

    @staticmethod
    def _mock_user_alerts(upn: str) -> list[dict[str, Any]]:
        return [
            {
                "AlertId": "mock-user-alert-001",
                "Title": "[DEMO] Anomalous token usage detected",
                "Severity": "Medium",
                "Category": "InitialAccess",
                "AccountUpn": upn,
                "AttackTechniques": ["T1528"],
            }
        ]
