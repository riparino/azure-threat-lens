"""Microsoft Defender XDR / Defender for Endpoint client."""

from __future__ import annotations

from typing import Any

from threatlens.azure._base import BaseAzureClient
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_BASE = "https://api.security.microsoft.com"
_SCOPE = "https://api.security.microsoft.com/.default"


class DefenderClient(BaseAzureClient):
    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.defender.tenant_id or cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_SCOPE],
        )
        self._enabled = cfg.defender.enabled

    def _url(self, path: str) -> str:
        return f"{_BASE}/api/{path.lstrip('/')}"

    async def get_user_alerts(self, upn: str, *, top: int = 20) -> list[dict[str, Any]]:
        if not self._enabled:
            return _mock_user_alerts(upn)
        query = f"""
AlertInfo
| where AccountUpn =~ '{upn}'
| join kind=inner AlertEvidence on AlertId
| top {top} by Timestamp desc
| project AlertId, Title, Severity, Category, AccountUpn, Timestamp, AttackTechniques
"""
        return await self.run_advanced_hunting(query)

    async def get_machine_alerts(self, machine_id: str, *, top: int = 20) -> list[dict[str, Any]]:
        if not self._enabled:
            return _mock_machine_alerts(machine_id)
        try:
            data = await self.get(self._url(f"machines/{machine_id}/alerts"),
                                  params={"$top": top, "$orderby": "alertCreationTime desc"})
            return data.get("value", [])  # type: ignore[return-value,union-attr]
        except Exception as exc:
            log.error("defender.get_machine_alerts.failed", error=str(exc))
            return []

    async def run_advanced_hunting(self, query: str) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        try:
            data = await self.post(self._url("advancedqueries/run"), json={"Query": query})
            return data.get("Results", [])  # type: ignore[return-value,union-attr]
        except Exception as exc:
            log.error("defender.advanced_hunting.failed", error=str(exc))
            return []


def _mock_user_alerts(upn: str) -> list[dict[str, Any]]:
    return [{"AlertId": "mock-001", "Title": "[DEMO] Anomalous token usage", "Severity": "Medium",
             "Category": "InitialAccess", "AccountUpn": upn, "AttackTechniques": ["T1528"]}]


def _mock_machine_alerts(machine_id: str) -> list[dict[str, Any]]:
    return [{"id": "mock-mde-001", "title": "[DEMO] Suspicious PowerShell", "severity": "High",
             "machineId": machine_id, "category": "Execution", "mitreTechniques": ["T1059.001"]}]
