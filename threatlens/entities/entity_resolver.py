from __future__ import annotations

import ipaddress

from threatlens.entities.azure_resource_resolver import AzureResourceResolver
from threatlens.entities.identity_resolver import IdentityResolver
from threatlens.entities.network_resolver import NetworkResolver


class EntityResolver:
    def __init__(
        self,
        identity_resolver: IdentityResolver,
        azure_resource_resolver: AzureResourceResolver,
        network_resolver: NetworkResolver,
    ) -> None:
        self.identity_resolver = identity_resolver
        self.azure_resource_resolver = azure_resource_resolver
        self.network_resolver = network_resolver

    async def resolve(self, entity: str) -> dict[str, object]:
        if entity.startswith("/subscriptions/"):
            return {"kind": "azure_resource", "data": await self.azure_resource_resolver.resolve(entity)}

        if "@" in entity:
            return {"kind": "identity", "data": await self.identity_resolver.resolve(entity)}

        try:
            ipaddress.ip_address(entity)
            return {"kind": "ip", "data": await self.network_resolver.resolve_ip(entity)}
        except ValueError:
            return {"kind": "unknown", "data": {"value": entity}}
