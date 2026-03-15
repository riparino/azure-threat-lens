"""Entity resolver – dispatches to the right resolver based on entity kind."""

from __future__ import annotations

import ipaddress
from typing import Any

from threatlens.models.entities import EntityKind, ResolvedEntity, ThreatIntelHit
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


def detect_kind(identifier: str) -> EntityKind:
    """Auto-detect entity kind from its identifier string."""
    try:
        ipaddress.ip_address(identifier)
        return EntityKind.IP
    except ValueError:
        pass
    if identifier.startswith("/subscriptions/"):
        return EntityKind.AZURE_RESOURCE
    if identifier.startswith(("http://", "https://")):
        return EntityKind.URL
    if len(identifier) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in identifier):
        return EntityKind.FILE_HASH
    if "." in identifier and "@" not in identifier:
        return EntityKind.HOST
    if "@" in identifier:
        return EntityKind.ACCOUNT
    return EntityKind.UNKNOWN


def score_to_label(score: float) -> str:
    if score >= 8.0:
        return "Critical"
    if score >= 6.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 1.0:
        return "Low"
    return "Clean"


class EntityResolver:
    """Unified entity resolution dispatcher.

    Routes entities to the appropriate specialised resolver (IP, host, identity,
    Azure resource) and returns a normalised ResolvedEntity.
    """

    def __init__(self) -> None:
        # Lazy imports to avoid loading Azure clients at package init time
        from threatlens.entities.azure_resource_resolver import AzureResourceResolver
        from threatlens.entities.identity_resolver import IdentityResolver
        from threatlens.entities.network_resolver import NetworkResolver

        self._network = NetworkResolver()
        self._azure = AzureResourceResolver()
        self._identity = IdentityResolver()

    async def resolve(
        self,
        identifier: str,
        kind: EntityKind | str | None = None,
    ) -> ResolvedEntity:
        """Resolve an entity by identifier, auto-detecting its kind if not given."""
        if kind is None:
            entity_kind = detect_kind(identifier)
        elif isinstance(kind, str):
            try:
                entity_kind = EntityKind(kind)
            except ValueError:
                entity_kind = EntityKind.UNKNOWN
        else:
            entity_kind = kind

        log.info("entity_resolver.resolve", identifier=identifier, kind=entity_kind.value)

        if entity_kind == EntityKind.IP:
            return await self._network.resolve_ip(identifier)
        if entity_kind == EntityKind.HOST:
            return await self._network.resolve_host(identifier)
        if entity_kind == EntityKind.URL:
            return await self._network.resolve_url(identifier)
        if entity_kind == EntityKind.FILE_HASH:
            return await self._network.resolve_hash(identifier)
        if entity_kind == EntityKind.AZURE_RESOURCE:
            return await self._azure.resolve(identifier)
        if entity_kind == EntityKind.ACCOUNT:
            return await self._identity.resolve(identifier)

        # Generic fallback
        return ResolvedEntity(
            entity_kind=entity_kind,
            identifier=identifier,
            display_name=identifier,
            context={"note": f"No specialised resolver for kind '{entity_kind.value}'"},
            risk_score=0.0,
            risk_label="Unknown",
        )
