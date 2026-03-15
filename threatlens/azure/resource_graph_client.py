from __future__ import annotations

from typing import Any


class ResourceGraphClient:
    async def get_resource(self, resource_id: str) -> dict[str, Any]:
        return {
            "resource_id": resource_id,
            "resource_type": "Microsoft.Compute/virtualMachines",
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "tags": {"environment": "prod"},
        }

    async def search_related_resources(self, resource_id: str) -> list[dict[str, Any]]:
        return [{"resource_id": f"{resource_id}/extensions/agent"}]
