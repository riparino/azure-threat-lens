from __future__ import annotations

from threatlens.azure.resource_graph_client import ResourceGraphClient


class AzureResourceResolver:
    def __init__(self, resource_graph_client: ResourceGraphClient | None = None) -> None:
        self._client = resource_graph_client or ResourceGraphClient()

    def resolve(self, resource_id: str) -> dict[str, str]:
        return self._client.get_resource_context(resource_id)
