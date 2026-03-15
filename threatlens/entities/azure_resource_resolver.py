from __future__ import annotations

from threatlens.azure.resource_graph_client import ResourceGraphClient


class AzureResourceResolver:
    def __init__(self, resource_graph_client: ResourceGraphClient) -> None:
        self.resource_graph_client = resource_graph_client

    async def resolve(self, resource_id: str) -> dict[str, object]:
        resource = await self.resource_graph_client.get_resource(resource_id)
        resource["related"] = await self.resource_graph_client.search_related_resources(resource_id)
        return resource
