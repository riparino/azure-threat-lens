from __future__ import annotations

from threatlens.azure.graph_client import GraphClient


class IdentityResolver:
    def __init__(self, graph_client: GraphClient | None = None) -> None:
        self._graph = graph_client or GraphClient()

    def resolve(self, identity: str) -> dict[str, str | bool]:
        return self._graph.get_identity(identity)
