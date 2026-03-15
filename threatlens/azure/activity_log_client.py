from __future__ import annotations


class ActivityLogClient:
    def query_resource_activity(self, resource_id: str) -> list[dict[str, str]]:
        return [
            {
                "resourceId": resource_id,
                "operationName": "Microsoft.Authorization/roleAssignments/write",
                "status": "Succeeded",
            }
        ]
