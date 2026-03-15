from __future__ import annotations

from threatlens.azure.graph_client import GraphClient


class IdentityResolver:
    def __init__(self, graph_client: GraphClient) -> None:
        self.graph_client = graph_client

    async def resolve(self, identity: str) -> dict[str, object]:
        return await self.graph_client.get_identity_profile(identity)
