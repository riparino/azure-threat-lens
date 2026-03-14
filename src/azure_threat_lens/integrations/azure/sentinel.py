"""Microsoft Sentinel REST API integration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.azure.base import BaseAzureClient
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.incident import Alert, AlertEntity, Incident, IncidentStatus, Severity

log = get_logger(__name__)

_ARM_BASE = "https://management.azure.com"
_MANAGEMENT_SCOPE = "https://management.azure.com/.default"


class SentinelClient(BaseAzureClient):
    """Client for the Microsoft Sentinel Incidents & Alerts API.

    Supports both single-workspace and Azure Lighthouse multi-workspace scenarios.
    Pass ``workspace`` to target a specific delegated workspace by name or ID;
    omit to use the primary workspace configured via environment variables.
    """

    def __init__(self, workspace: str | None = None) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_MANAGEMENT_SCOPE],
            timeout=cfg.get_yaml("azure", "request_timeout", default=30),
            max_retries=cfg.get_yaml("azure", "max_retries", default=3),
        )
        # Resolve workspace – supports Lighthouse delegated workspaces
        if workspace:
            ws_cfg = cfg.sentinel.get_workspace(workspace, cfg.azure.subscription_id)
            if ws_cfg is None:
                raise ValueError(
                    f"Workspace '{workspace}' not found. "
                    f"Available: {[w.display_name or w.workspace_name for w in cfg.sentinel.all_workspaces(cfg.azure.subscription_id)]}"
                )
            self._sub = ws_cfg.subscription_id or cfg.azure.subscription_id
            self._rg = ws_cfg.resource_group
            self._ws = ws_cfg.workspace_name
            log.info("sentinel.using_lighthouse_workspace", workspace=ws_cfg.display_name or ws_cfg.workspace_name)
        else:
            self._sub = cfg.azure.subscription_id
            self._rg = cfg.sentinel.resource_group
            self._ws = cfg.sentinel.workspace_name
        self._api_ver = cfg.sentinel.api_version

    def _incidents_url(self, incident_id: str = "") -> str:
        base = (
            f"{_ARM_BASE}/subscriptions/{self._sub}"
            f"/resourceGroups/{self._rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._ws}"
            f"/providers/Microsoft.SecurityInsights/incidents"
        )
        return f"{base}/{incident_id}" if incident_id else base

    # ── Incidents ──────────────────────────────────────────────────────────────

    async def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: Severity | None = None,
        lookback_hours: int = 72,
        top: int = 50,
    ) -> list[Incident]:
        """Fetch recent Sentinel incidents, optionally filtered by status/severity."""
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        odata_filter = f"properties/createdTimeUtc ge {since.isoformat()}"
        if status:
            odata_filter += f" and properties/status eq '{status.value}'"
        if severity:
            odata_filter += f" and properties/severity eq '{severity.value}'"

        params: dict[str, Any] = {
            "api-version": self._api_ver,
            "$filter": odata_filter,
            "$orderby": "properties/createdTimeUtc desc",
            "$top": top,
        }
        log.info("sentinel.list_incidents", lookback_hours=lookback_hours, top=top)

        try:
            data = await self.get(self._incidents_url(), params=params)
            raw_incidents: list[dict[str, Any]] = data.get("value", [])  # type: ignore[union-attr]
            return [self._parse_incident(r) for r in raw_incidents]
        except Exception as exc:
            log.error("sentinel.list_incidents.failed", error=str(exc))
            # Return empty list with a placeholder so callers can handle gracefully
            return self._mock_incidents(lookback_hours)

    async def get_incident(self, incident_id: str) -> Incident:
        """Fetch a single Sentinel incident by ID."""
        log.info("sentinel.get_incident", incident_id=incident_id)
        try:
            data = await self.get(self._incidents_url(incident_id), params={"api-version": self._api_ver})
            return self._parse_incident(data)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("sentinel.get_incident.failed", incident_id=incident_id, error=str(exc))
            return self._mock_incident(incident_id)

    async def get_incident_alerts(self, incident_id: str) -> list[Alert]:
        """Fetch alerts attached to a Sentinel incident."""
        url = f"{self._incidents_url(incident_id)}/alerts"
        log.info("sentinel.get_incident_alerts", incident_id=incident_id)
        try:
            data = await self.post(url, params={"api-version": self._api_ver}, json={})
            raw_alerts: list[dict[str, Any]] = data.get("value", [])  # type: ignore[union-attr]
            return [self._parse_alert(a) for a in raw_alerts]
        except Exception as exc:
            log.error("sentinel.get_incident_alerts.failed", error=str(exc))
            return []

    async def get_incident_entities(self, incident_id: str) -> list[AlertEntity]:
        """Fetch entities attached to a Sentinel incident."""
        url = f"{self._incidents_url(incident_id)}/entities"
        log.info("sentinel.get_incident_entities", incident_id=incident_id)
        try:
            data = await self.post(url, params={"api-version": self._api_ver}, json={})
            raw: list[dict[str, Any]] = data.get("entities", [])  # type: ignore[union-attr]
            return [self._parse_entity(e) for e in raw]
        except Exception as exc:
            log.error("sentinel.get_incident_entities.failed", error=str(exc))
            return []

    # ── Parsers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_incident(raw: dict[str, Any]) -> Incident:
        props = raw.get("properties", {})
        return Incident.model_validate(
            {
                "incidentId": raw.get("name", ""),
                "incidentNumber": props.get("incidentNumber", 0),
                "title": props.get("title", ""),
                "description": props.get("description", ""),
                "severity": props.get("severity", "Informational"),
                "status": props.get("status", "New"),
                "owner": props.get("owner", {}),
                "labels": props.get("labels", []),
                "tactics": props.get("tactics", []),
                "techniques": props.get("techniques", []),
                "createdTimeUtc": props.get("createdTimeUtc"),
                "lastModifiedTimeUtc": props.get("lastModifiedTimeUtc"),
                "firstActivityTimeUtc": props.get("firstActivityTimeUtc"),
                "lastActivityTimeUtc": props.get("lastActivityTimeUtc"),
                "relatedAlertIds": props.get("relatedAlertIds", []),
                "providerIncidentId": props.get("providerIncidentId", ""),
            }
        )

    @staticmethod
    def _parse_alert(raw: dict[str, Any]) -> Alert:
        props = raw.get("properties", {})
        return Alert.model_validate(
            {
                "systemAlertId": props.get("systemAlertId", raw.get("name", "")),
                "alertDisplayName": props.get("alertDisplayName", ""),
                "severity": props.get("severity", "Informational"),
                "description": props.get("description", ""),
                "providerName": props.get("providerName", ""),
                "productName": props.get("productName", ""),
                "status": props.get("status", ""),
                "timeGenerated": props.get("timeGenerated"),
                "tactics": props.get("tactics", []),
                "techniques": props.get("techniques", []),
                "extendedProperties": props.get("extendedProperties", {}),
            }
        )

    @staticmethod
    def _parse_entity(raw: dict[str, Any]) -> AlertEntity:
        kind = raw.get("kind", "Unknown")
        props = raw.get("properties", {})
        return AlertEntity.model_validate(
            {
                "entityType": kind,
                "friendlyName": props.get("friendlyName", ""),
                "properties": props,
            }
        )

    # ── Mock data for offline/demo mode ───────────────────────────────────────

    @staticmethod
    def _mock_incidents(lookback_hours: int) -> list[Incident]:
        """Return a sample incident list for demo/testing when API is unavailable."""
        log.warning("sentinel.using_mock_data", reason="API not configured or unreachable")
        return [
            Incident.model_validate(
                {
                    "incidentId": "mock-incident-001",
                    "incidentNumber": 1001,
                    "title": "[DEMO] Suspicious sign-in from anonymous IP",
                    "description": "A user signed in from a known anonymous proxy IP.",
                    "severity": "High",
                    "status": "New",
                    "tactics": ["InitialAccess"],
                    "techniques": ["T1078"],
                    "createdTimeUtc": datetime.now(timezone.utc).isoformat(),
                }
            ),
            Incident.model_validate(
                {
                    "incidentId": "mock-incident-002",
                    "incidentNumber": 1002,
                    "title": "[DEMO] Impossible travel detected",
                    "description": "Sign-ins from geographically impossible locations within 2 hours.",
                    "severity": "Medium",
                    "status": "Active",
                    "tactics": ["CredentialAccess"],
                    "techniques": ["T1110"],
                    "createdTimeUtc": datetime.now(timezone.utc).isoformat(),
                }
            ),
        ]

    @staticmethod
    def _mock_incident(incident_id: str) -> Incident:
        return Incident.model_validate(
            {
                "incidentId": incident_id,
                "incidentNumber": 9999,
                "title": f"[DEMO] Mock incident {incident_id}",
                "description": "This is a placeholder incident returned when the Sentinel API is not configured.",
                "severity": "Medium",
                "status": "New",
                "tactics": ["Execution"],
                "techniques": ["T1059"],
                "createdTimeUtc": datetime.now(timezone.utc).isoformat(),
            }
        )
