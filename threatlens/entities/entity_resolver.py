from __future__ import annotations

from typing import Any

from threatlens.entities.azure_resource_resolver import AzureResourceResolver
from threatlens.entities.identity_resolver import IdentityResolver
from threatlens.entities.network_resolver import NetworkResolver


class EntityResolver:
    def __init__(self) -> None:
        self._identity = IdentityResolver()
        self._network = NetworkResolver()
        self._resource = AzureResourceResolver()

    def resolve(self, entity: str) -> dict[str, Any]:
        if entity.startswith("/subscriptions/"):
            return {"type": "azure_resource", "data": self._resource.resolve(entity)}
        if "@" in entity:
            return {"type": "identity", "data": self._identity.resolve(entity)}
        return {"type": "network", "data": self._network.resolve(entity)}
