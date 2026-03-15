from __future__ import annotations


class ActivityLogClient:
    async def list_activity(self, resource_id: str) -> list[dict[str, str]]:
        return [
            {"operation": "Microsoft.Authorization/roleAssignments/write", "status": "Succeeded"},
            {"operation": "Microsoft.Compute/virtualMachines/write", "status": "Succeeded"},
        ]
