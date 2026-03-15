"""Azure resource resolver – resolves any ARM resource ID using Resource Graph.

Designed to handle ALL Azure resource types generically. Rather than writing
a specific API call per resource type, the resolver queries Azure Resource Graph
which returns metadata for any resource the credential has access to.
"""

from __future__ import annotations

from typing import Any

from threatlens.entities.entity_resolver import score_to_label
from threatlens.models.entities import EntityKind, ResolvedEntity
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class AzureResourceResolver:
    """Resolves Azure ARM resource IDs using Resource Graph.

    Works generically across thousands of resource types without needing
    resource-type-specific implementations.
    """

    def __init__(self) -> None:
        from threatlens.azure.resource_graph_client import ResourceGraphClient
        from threatlens.azure.activity_log_client import ActivityLogClient
        self._rg = ResourceGraphClient()
        self._al = ActivityLogClient()

    async def resolve(self, resource_id: str) -> ResolvedEntity:
        """Resolve any Azure resource by its ARM resource ID."""
        log.info("azure_resource_resolver.resolve", resource_id=resource_id[:80])

        # Generic Resource Graph lookup – works for any resource type
        details = await self._rg.get_resource(resource_id)

        if details is None:
            return ResolvedEntity(
                entity_kind=EntityKind.AZURE_RESOURCE,
                identifier=resource_id,
                display_name=_name_from_id(resource_id),
                context={"found": False, "note": "Resource not found or no access"},
                risk_score=0.0,
                risk_label="Unknown",
            )

        # Get recent admin operations against this resource
        recent_ops = await self._al.list_resource_operations(resource_id, lookback_hours=48)

        indicators = _assess_resource_indicators(details, recent_ops)
        risk_score = _compute_resource_risk(details, recent_ops)

        return ResolvedEntity(
            entity_kind=EntityKind.AZURE_RESOURCE,
            identifier=resource_id,
            display_name=details.get("name", _name_from_id(resource_id)),
            context={
                "type": details.get("type", ""),
                "location": details.get("location", ""),
                "resource_group": details.get("resourceGroup", ""),
                "subscription_id": details.get("subscriptionId", ""),
                "tags": details.get("tags", {}),
                "recent_operations_count": len(recent_ops),
            },
            risk_score=risk_score,
            risk_label=score_to_label(risk_score),
            risk_indicators=indicators,
            azure_resource_details={
                "resource": details,
                "recent_operations": recent_ops[:10],
            },
        )


def _name_from_id(resource_id: str) -> str:
    """Extract the resource name from an ARM resource ID."""
    parts = resource_id.rstrip("/").split("/")
    return parts[-1] if parts else resource_id


def _assess_resource_indicators(
    details: dict[str, Any], ops: list[dict[str, Any]]
) -> list[str]:
    indicators: list[str] = []
    resource_type = details.get("type", "").lower()

    # High-value resource types
    sensitive_types = {
        "microsoft.keyvault/vaults",
        "microsoft.storage/storageaccounts",
        "microsoft.compute/virtualmachines",
        "microsoft.sql/servers",
        "microsoft.documentdb/databaseaccounts",
    }
    if any(resource_type.startswith(t) for t in sensitive_types):
        indicators.append(f"Sensitive resource type: {details.get('type', '')}")

    # Recent privilege changes
    priv_ops = [
        o for o in ops
        if "roleAssignment" in o.get("operation_name", "")
        or "authorization" in o.get("operation_name", "").lower()
    ]
    if priv_ops:
        indicators.append(f"{len(priv_ops)} privilege-related operation(s) in last 48h")

    # High operation volume
    if len(ops) > 20:
        indicators.append(f"High operation volume: {len(ops)} operations in last 48h")

    return indicators


def _compute_resource_risk(details: dict[str, Any], ops: list[dict[str, Any]]) -> float:
    score = 0.0
    resource_type = details.get("type", "").lower()
    sensitive_types = {
        "microsoft.keyvault/vaults": 3.0,
        "microsoft.storage/storageaccounts": 2.5,
        "microsoft.compute/virtualmachines": 2.0,
        "microsoft.sql/servers": 2.5,
    }
    for t, v in sensitive_types.items():
        if resource_type.startswith(t):
            score += v
            break

    priv_ops = sum(1 for o in ops if "roleAssignment" in o.get("operation_name", ""))
    score += min(priv_ops * 1.5, 4.0)

    return round(min(score, 10.0), 2)
