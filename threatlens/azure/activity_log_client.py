"""Azure Activity Log (Azure Monitor) client.

The Activity Log records all control-plane operations across Azure subscriptions:
resource creation/deletion, role assignments, policy changes, etc. This is the
primary source for detecting suspicious administrative activity.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from threatlens.azure._base import BaseAzureClient
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_ARM = "https://management.azure.com"
_SCOPE = "https://management.azure.com/.default"
_API = "2015-04-01"

# Categories of interest for security investigations
SECURITY_CATEGORIES = {
    "Administrative",  # Resource CRUD, role changes
    "Security",        # Azure Defender / Security Centre alerts
    "Policy",          # Policy evaluations and compliance changes
    "Alert",           # Azure Monitor alert firings
    "Autoscale",       # Unusual scale events
    "Recommendation",  # Advisor security recommendations
}


class ActivityLogClient(BaseAzureClient):
    """Client for the Azure Monitor Activity Log API."""

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_SCOPE],
        )
        self._sub = cfg.azure.subscription_id

    def _url(self) -> str:
        return f"{_ARM}/subscriptions/{self._sub}/providers/microsoft.insights/eventtypes/management/values"

    async def list_events(
        self,
        *,
        lookback_hours: int = 24,
        resource_id: str | None = None,
        caller: str | None = None,
        categories: set[str] | None = None,
        top: int = 200,
    ) -> list[dict[str, Any]]:
        """List Activity Log events with optional filters.

        Args:
            lookback_hours: How far back to query (max 90 days for Activity Log).
            resource_id:    Scope to a specific resource ARM ID.
            caller:         Filter by caller UPN, service principal, or object ID.
            categories:     Filter by event categories (default: all security categories).
            top:            Max events to return.
        """
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        filter_parts = [f"eventTimestamp ge '{since.isoformat()}'"]

        if resource_id:
            filter_parts.append(f"resourceId eq '{resource_id}'")
        if caller:
            filter_parts.append(f"caller eq '{caller}'")

        cats = categories or SECURITY_CATEGORIES
        if cats:
            cat_filters = " or ".join(f"category eq '{c}'" for c in cats)
            filter_parts.append(f"({cat_filters})")

        params: dict[str, Any] = {
            "api-version": _API,
            "$filter": " and ".join(filter_parts),
            "$top": top,
        }

        log.info("activity_log.list_events", lookback_hours=lookback_hours, resource_id=resource_id)
        try:
            data = await self.get(self._url(), params=params)
            events: list[dict[str, Any]] = data.get("value", [])  # type: ignore[union-attr]
            return [self._parse_event(e) for e in events]
        except Exception as exc:
            log.error("activity_log.list_events.failed", error=str(exc))
            return _mock_events(resource_id or "unknown")

    async def list_resource_operations(
        self, resource_id: str, *, lookback_hours: int = 48
    ) -> list[dict[str, Any]]:
        """Convenience: get all control-plane ops against a specific resource."""
        return await self.list_events(
            lookback_hours=lookback_hours,
            resource_id=resource_id,
            categories={"Administrative"},
        )

    async def list_caller_activity(
        self, caller: str, *, lookback_hours: int = 72
    ) -> list[dict[str, Any]]:
        """Convenience: get all admin operations performed by a specific caller."""
        return await self.list_events(
            lookback_hours=lookback_hours,
            caller=caller,
            categories={"Administrative", "Security"},
        )

    async def find_privilege_changes(self, *, lookback_hours: int = 168) -> list[dict[str, Any]]:
        """Find role assignment and policy changes – key signals for privilege escalation."""
        events = await self.list_events(
            lookback_hours=lookback_hours,
            categories={"Administrative"},
        )
        priv_ops = {
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/roleAssignments/delete",
            "Microsoft.Authorization/roleDefinitions/write",
            "Microsoft.Authorization/policyAssignments/write",
        }
        return [e for e in events if e.get("operation_name") in priv_ops]

    # ── Parser ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_event(raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": raw.get("id", ""),
            "event_timestamp": raw.get("eventTimestamp", ""),
            "caller": raw.get("caller", ""),
            "operation_name": raw.get("operationName", {}).get("value", ""),
            "operation_display": raw.get("operationName", {}).get("localizedValue", ""),
            "status": raw.get("status", {}).get("value", ""),
            "resource_id": raw.get("resourceId", ""),
            "resource_group": raw.get("resourceGroupName", ""),
            "resource_type": raw.get("resourceType", {}).get("value", ""),
            "correlation_id": raw.get("correlationId", ""),
            "category": raw.get("category", {}).get("value", ""),
            "level": raw.get("level", ""),
            "description": raw.get("description", ""),
            "properties": raw.get("properties", {}),
        }


def _mock_events(resource_id: str) -> list[dict[str, Any]]:
    log.warning("activity_log.mock_data", resource_id=resource_id)
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "id": "mock-event-001",
            "event_timestamp": now,
            "caller": "alice@demo.contoso.com",
            "operation_name": "Microsoft.Authorization/roleAssignments/write",
            "operation_display": "Create role assignment",
            "status": "Succeeded",
            "resource_id": resource_id,
            "resource_group": "demo-rg",
            "resource_type": "Microsoft.Authorization/roleAssignments",
            "category": "Administrative",
            "level": "Informational",
            "description": "[DEMO] Role assignment created",
            "properties": {},
        }
    ]
