"""Resource access analysis – detects anomalous access patterns on Azure resources."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from threatlens.utils.logging import get_logger

log = get_logger(__name__)

# Resource operations considered sensitive for investigation
_SENSITIVE_OPS = {
    "microsoft.keyvault/vaults/secrets/read": "Key Vault secret read",
    "microsoft.keyvault/vaults/keys/use/action": "Key Vault key use",
    "microsoft.storage/storageaccounts/listkeys/action": "Storage account keys listed",
    "microsoft.compute/virtualmachines/runcommand/action": "VM run-command executed",
    "microsoft.compute/virtualmachines/extensions/write": "VM extension installed",
    "microsoft.authorization/roleassignments/write": "RBAC role assigned",
    "microsoft.network/networksecuritygroups/write": "NSG modified",
    "microsoft.network/firewallpolicies/write": "Firewall policy modified",
    "microsoft.web/sites/config/write": "App Service config modified",
}


class ResourceAccessAnalyser:
    """Analyses access patterns and anomalies against Azure resources."""

    def __init__(self) -> None:
        from threatlens.azure.activity_log_client import ActivityLogClient
        from threatlens.azure.resource_graph_client import ResourceGraphClient
        self._activity = ActivityLogClient()
        self._rg = ResourceGraphClient()

    async def analyse_resource(
        self, resource_id: str, *, lookback_hours: int = 48
    ) -> dict[str, Any]:
        """Analyse activity log for a specific resource."""
        log.info("resource_access.analyse", resource_id=resource_id[:80])
        events = await self._activity.list_resource_operations(resource_id, lookback_hours=lookback_hours)
        resource_details = await self._rg.get_resource(resource_id)
        return analyse_resource_events(events, resource_details or {})

    async def find_cross_resource_access(
        self, caller: str, *, lookback_hours: int = 72
    ) -> dict[str, Any]:
        """Find all resources accessed by a specific caller."""
        events = await self._activity.list_caller_activity(caller, lookback_hours=lookback_hours)
        return analyse_caller_pattern(events, caller)


# ── Pure analysis functions ────────────────────────────────────────────────────

def analyse_resource_events(
    events: list[dict[str, Any]], resource_details: dict[str, Any]
) -> dict[str, Any]:
    findings: list[str] = []
    risk_score = 0.0

    sensitive = [
        e for e in events
        if e.get("operation_name", "").lower() in _SENSITIVE_OPS
    ]
    if sensitive:
        for e in sensitive[:5]:
            op = e.get("operation_name", "").lower()
            findings.append(
                f"Sensitive operation by {e.get('caller', '?')}: {_SENSITIVE_OPS.get(op, op)}"
            )
        risk_score += min(len(sensitive) * 1.5, 5.0)

    # Multiple distinct callers
    callers = {e.get("caller", "") for e in events if e.get("caller")}
    if len(callers) > 5:
        findings.append(f"Unusual number of distinct callers: {len(callers)}")
        risk_score += 1.5

    # Failed operations
    failures = [e for e in events if e.get("status", "").lower() == "failed"]
    if failures:
        findings.append(f"{len(failures)} failed operation(s) – possible access denied / probing")
        risk_score += min(len(failures) * 0.5, 2.0)

    return {
        "total_events": len(events),
        "sensitive_operations": len(sensitive),
        "distinct_callers": len(callers),
        "failed_operations": len(failures),
        "findings": findings,
        "risk_score": round(min(risk_score, 10.0), 2),
        "resource_type": resource_details.get("type", ""),
    }


def analyse_caller_pattern(events: list[dict[str, Any]], caller: str) -> dict[str, Any]:
    if not events:
        return {"caller": caller, "resource_count": 0, "findings": [], "risk_score": 0.0}

    resource_ids = {e.get("resource_id", "") for e in events if e.get("resource_id")}
    op_counts = Counter(e.get("operation_name", "") for e in events)
    sensitive = [
        op for op in op_counts
        if op.lower() in _SENSITIVE_OPS
    ]

    findings: list[str] = []
    risk_score = 0.0

    if len(resource_ids) > 20:
        findings.append(f"Caller accessed {len(resource_ids)} distinct resources – possible lateral movement")
        risk_score += 2.0

    if sensitive:
        findings.append(f"Sensitive operations performed: {', '.join(sensitive[:3])}")
        risk_score += min(len(sensitive) * 1.0, 4.0)

    return {
        "caller": caller,
        "resource_count": len(resource_ids),
        "operation_count": len(events),
        "sensitive_operations": sensitive,
        "top_operations": op_counts.most_common(5),
        "findings": findings,
        "risk_score": round(min(risk_score, 10.0), 2),
    }
