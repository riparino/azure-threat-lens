"""Privilege escalation analysis – detects RBAC and Entra ID privilege abuse."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from threatlens.utils.logging import get_logger

log = get_logger(__name__)

# Azure RBAC roles that grant broad control-plane access
_HIGH_PRIVILEGE_ROLES = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Security Admin",
    "Network Contributor",
    "Virtual Machine Contributor",
    "Storage Account Contributor",
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
}

# Operations that represent privilege escalation via Activity Log
_ESCALATION_OPS = {
    "Microsoft.Authorization/roleAssignments/write": "RBAC role assignment added",
    "Microsoft.Authorization/roleDefinitions/write": "Custom role definition created/modified",
    "Microsoft.Authorization/elevateAccess/action": "Global Admin elevated to User Access Admin",
    "Microsoft.Authorization/policyAssignments/write": "Policy assignment modified",
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": "Managed identity assigned",
}


class PrivilegeEscalationAnalyser:
    """Detects privilege escalation patterns in Azure RBAC and Activity Logs."""

    def __init__(self) -> None:
        from threatlens.azure.activity_log_client import ActivityLogClient
        from threatlens.azure.resource_graph_client import ResourceGraphClient
        self._activity = ActivityLogClient()
        self._rg = ResourceGraphClient()

    async def find_recent_escalations(
        self, caller: str | None = None, *, lookback_hours: int = 168
    ) -> list[dict[str, Any]]:
        """Find privilege escalation events in the Activity Log."""
        log.info("privilege_escalation.find", caller=caller, lookback_hours=lookback_hours)
        events = await self._activity.find_privilege_changes(lookback_hours=lookback_hours)
        if caller:
            events = [e for e in events if e.get("caller", "").lower() == caller.lower()]
        return [_annotate_escalation(e) for e in events]

    async def assess_role_assignments(self, scope: str) -> dict[str, Any]:
        """Assess role assignments at a given scope for over-privileged principals."""
        kql = f"""
AuthorizationResources
| where type == 'microsoft.authorization/roleassignments'
| where id startswith '{scope}'
| project principalId, roleDefinitionId, scope=properties.scope, createdOn=properties.createdOn
| limit 200
"""
        assignments = await self._rg.query(kql)
        return _evaluate_role_assignments(assignments)


# ── Pure analysis functions ────────────────────────────────────────────────────

def _annotate_escalation(event: dict[str, Any]) -> dict[str, Any]:
    op = event.get("operation_name", "")
    return {
        **event,
        "escalation_type": _ESCALATION_OPS.get(op, "Unknown privilege operation"),
        "risk_level": "high" if op in _ESCALATION_OPS else "medium",
    }


def _evaluate_role_assignments(assignments: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[str] = []
    risk_score = 0.0
    # Detect broad scope assignments (subscription or management group level)
    broad_scope = [a for a in assignments if _is_broad_scope(str(a.get("scope", "")))]
    if broad_scope:
        findings.append(f"{len(broad_scope)} role assignments at subscription or higher scope")
        risk_score += min(len(broad_scope) * 0.5, 3.0)
    # Recent assignments (within 24h) are higher risk
    now = datetime.now(timezone.utc)
    recent = []
    for a in assignments:
        created = a.get("createdOn", "")
        if created:
            try:
                dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                if (now - dt).total_seconds() < 86400:
                    recent.append(a)
            except ValueError:
                pass
    if recent:
        findings.append(f"{len(recent)} role assignments created in the last 24h")
        risk_score += min(len(recent) * 1.0, 4.0)
    return {
        "total_assignments": len(assignments),
        "broad_scope_assignments": len(broad_scope),
        "recent_assignments": len(recent),
        "findings": findings,
        "risk_score": round(min(risk_score, 10.0), 2),
    }


def _is_broad_scope(scope: str) -> bool:
    """Return True if scope is at subscription or management group level."""
    parts = scope.strip("/").split("/")
    # /subscriptions/{id} = 2 parts, /providers/Microsoft.Management/... = broader
    return len(parts) <= 2 or "Microsoft.Management" in scope
