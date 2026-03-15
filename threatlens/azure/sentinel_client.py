"""Microsoft Sentinel REST API client."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from threatlens.azure._base import BaseAzureClient
from threatlens.models.incidents import Alert, Incident, IncidentStatus, RawEntity, Severity
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_ARM = "https://management.azure.com"
_SCOPE = "https://management.azure.com/.default"


class SentinelClient(BaseAzureClient):
    """Client for the Microsoft Sentinel Incidents & Alerts API.

    Supports Azure Lighthouse multi-workspace scenarios via the ``workspace``
    parameter, which resolves against ATL_SENTINEL_WORKSPACES.
    """

    def __init__(self, workspace: str | None = None) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_SCOPE],
            timeout=cfg.get_yaml("azure", "request_timeout", default=30),
            max_retries=cfg.get_yaml("azure", "max_retries", default=3),
        )
        if workspace:
            ws = cfg.sentinel.get_workspace(workspace, cfg.azure.subscription_id)
            if ws is None:
                available = [w.display_name or w.workspace_name for w in cfg.sentinel.all_workspaces(cfg.azure.subscription_id)]
                raise ValueError(f"Workspace '{workspace}' not found. Available: {available}")
            self._sub = ws.subscription_id or cfg.azure.subscription_id
            self._rg = ws.resource_group
            self._ws = ws.workspace_name
            log.info("sentinel.lighthouse_workspace", workspace=ws.display_name or ws.workspace_name)
        else:
            self._sub = cfg.azure.subscription_id
            self._rg = cfg.sentinel.resource_group
            self._ws = cfg.sentinel.workspace_name
        self._api = cfg.sentinel.api_version

    def _url(self, suffix: str = "") -> str:
        base = (
            f"{_ARM}/subscriptions/{self._sub}/resourceGroups/{self._rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._ws}"
            f"/providers/Microsoft.SecurityInsights/incidents"
        )
        return f"{base}/{suffix}" if suffix else base

    # ── Incidents ──────────────────────────────────────────────────────────────

    async def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: Severity | None = None,
        lookback_hours: int = 72,
        top: int = 50,
    ) -> list[Incident]:
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        f = f"properties/createdTimeUtc ge {since.isoformat()}"
        if status:
            f += f" and properties/status eq '{status.value}'"
        if severity:
            f += f" and properties/severity eq '{severity.value}'"
        params: dict[str, Any] = {
            "api-version": self._api,
            "$filter": f,
            "$orderby": "properties/createdTimeUtc desc",
            "$top": top,
        }
        log.info("sentinel.list_incidents", lookback_hours=lookback_hours, top=top)
        try:
            data = await self.get(self._url(), params=params)
            return [self._parse_incident(r) for r in data.get("value", [])]  # type: ignore[union-attr]
        except Exception as exc:
            log.error("sentinel.list_incidents.failed", error=str(exc))
            return _mock_incidents()

    async def get_incident(self, incident_id: str) -> Incident:
        log.info("sentinel.get_incident", incident_id=incident_id)
        try:
            data = await self.get(self._url(incident_id), params={"api-version": self._api})
            return self._parse_incident(data)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("sentinel.get_incident.failed", error=str(exc))
            return _mock_incident(incident_id)

    async def get_incident_alerts(self, incident_id: str) -> list[Alert]:
        url = self._url(f"{incident_id}/alerts")
        try:
            data = await self.post(url, params={"api-version": self._api}, json={})
            return [self._parse_alert(a) for a in data.get("value", [])]  # type: ignore[union-attr]
        except Exception as exc:
            log.error("sentinel.get_incident_alerts.failed", error=str(exc))
            return []

    async def get_incident_entities(self, incident_id: str) -> list[RawEntity]:
        url = self._url(f"{incident_id}/entities")
        try:
            data = await self.post(url, params={"api-version": self._api}, json={})
            return [self._parse_entity(e) for e in data.get("entities", [])]  # type: ignore[union-attr]
        except Exception as exc:
            log.error("sentinel.get_incident_entities.failed", error=str(exc))
            return []

    # ── Parsers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_incident(raw: dict[str, Any]) -> Incident:
        p = raw.get("properties", {})
        return Incident.model_validate({
            "incidentId": raw.get("name", ""),
            "incidentNumber": p.get("incidentNumber", 0),
            "title": p.get("title", ""),
            "description": p.get("description", ""),
            "severity": p.get("severity", "Informational"),
            "status": p.get("status", "New"),
            "owner": p.get("owner", {}),
            "labels": p.get("labels", []),
            "tactics": p.get("tactics", []),
            "techniques": p.get("techniques", []),
            "createdTimeUtc": p.get("createdTimeUtc"),
            "lastModifiedTimeUtc": p.get("lastModifiedTimeUtc"),
            "firstActivityTimeUtc": p.get("firstActivityTimeUtc"),
            "lastActivityTimeUtc": p.get("lastActivityTimeUtc"),
            "relatedAlertIds": p.get("relatedAlertIds", []),
            "providerIncidentId": p.get("providerIncidentId", ""),
        })

    @staticmethod
    def _parse_alert(raw: dict[str, Any]) -> Alert:
        p = raw.get("properties", {})
        return Alert.model_validate({
            "systemAlertId": p.get("systemAlertId", raw.get("name", "")),
            "alertDisplayName": p.get("alertDisplayName", ""),
            "severity": p.get("severity", "Informational"),
            "description": p.get("description", ""),
            "providerName": p.get("providerName", ""),
            "productName": p.get("productName", ""),
            "status": p.get("status", ""),
            "timeGenerated": p.get("timeGenerated"),
            "tactics": p.get("tactics", []),
            "techniques": p.get("techniques", []),
            "extendedProperties": p.get("extendedProperties", {}),
        })

    @staticmethod
    def _parse_entity(raw: dict[str, Any]) -> RawEntity:
        return RawEntity.model_validate({
            "entityType": raw.get("kind", "Unknown"),
            "friendlyName": raw.get("properties", {}).get("friendlyName", ""),
            "properties": raw.get("properties", {}),
        })


# ── Demo / offline mock data ───────────────────────────────────────────────────

def _mock_incidents() -> list[Incident]:
    log.warning("sentinel.mock_data")
    now = datetime.now(timezone.utc).isoformat()
    return [
        Incident.model_validate({"incidentId": "mock-001", "incidentNumber": 1001,
            "title": "[DEMO] Suspicious sign-in from anonymous IP", "severity": "High",
            "status": "New", "tactics": ["InitialAccess"], "techniques": ["T1078"],
            "createdTimeUtc": now}),
        Incident.model_validate({"incidentId": "mock-002", "incidentNumber": 1002,
            "title": "[DEMO] Impossible travel detected", "severity": "Medium",
            "status": "Active", "tactics": ["CredentialAccess"], "techniques": ["T1110"],
            "createdTimeUtc": now}),
    ]


def _mock_incident(incident_id: str) -> Incident:
    return Incident.model_validate({
        "incidentId": incident_id, "incidentNumber": 9999,
        "title": f"[DEMO] Mock incident {incident_id}", "severity": "Medium",
        "status": "New", "tactics": ["Execution"], "techniques": ["T1059"],
        "createdTimeUtc": datetime.now(timezone.utc).isoformat(),
    })
