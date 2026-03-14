"""Entity context resolution – enriches Azure entities with contextual data."""

from __future__ import annotations

import ipaddress
from typing import Any

from azure_threat_lens.integrations.azure.resource_graph import ResourceGraphClient
from azure_threat_lens.integrations.threat_intel.enricher import ThreatIntelEnricher
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import EntityKind, EntityResolutionResult, ThreatIntelHit

log = get_logger(__name__)


def _detect_kind(identifier: str) -> EntityKind:
    """Auto-detect entity kind from the identifier string."""
    try:
        ipaddress.ip_address(identifier)
        return EntityKind.IP
    except ValueError:
        pass
    if identifier.startswith("/subscriptions/"):
        return EntityKind.AZURE_RESOURCE
    if "." in identifier and not identifier.startswith("http"):
        # Could be a hostname or domain – treat as host for now
        return EntityKind.HOST
    if identifier.startswith("http://") or identifier.startswith("https://"):
        return EntityKind.URL
    if len(identifier) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in identifier):
        return EntityKind.FILE_HASH
    return EntityKind.UNKNOWN


class EntityResolver:
    """Resolves and enriches Azure entities with contextual + threat intel data."""

    def __init__(self) -> None:
        self._resource_graph = ResourceGraphClient()
        self._ti = ThreatIntelEnricher()

    async def resolve(
        self,
        identifier: str,
        kind: EntityKind | str | None = None,
    ) -> EntityResolutionResult:
        """Resolve entity context. Auto-detects kind if not specified."""
        if kind is None:
            entity_kind = _detect_kind(identifier)
        elif isinstance(kind, str):
            entity_kind = EntityKind(kind)
        else:
            entity_kind = kind

        log.info("entity.resolve", identifier=identifier, kind=entity_kind.value)

        resolver_map = {
            EntityKind.IP: self._resolve_ip,
            EntityKind.HOST: self._resolve_host,
            EntityKind.AZURE_RESOURCE: self._resolve_azure_resource,
            EntityKind.URL: self._resolve_url,
            EntityKind.FILE_HASH: self._resolve_hash,
        }

        resolver = resolver_map.get(entity_kind, self._resolve_generic)
        return await resolver(identifier, entity_kind)

    # ── IP resolution ──────────────────────────────────────────────────────────

    async def _resolve_ip(self, ip: str, kind: EntityKind) -> EntityResolutionResult:
        ti_hits = await self._ti.enrich_ip(ip)
        azure_resources = await self._resource_graph.find_resources_by_ip(ip)
        risk_score = ThreatIntelEnricher.aggregate_risk_score(ti_hits)

        try:
            addr = ipaddress.ip_address(ip)
            is_private = addr.is_private
        except ValueError:
            is_private = False

        context: dict[str, Any] = {
            "is_private": is_private,
            "azure_resources_count": len(azure_resources),
        }
        if ti_hits:
            context["threat_intel_summary"] = {
                h.provider: {"malicious": h.malicious, "score": h.score}
                for h in ti_hits
            }

        return EntityResolutionResult(
            entity_kind=kind,
            identifier=ip,
            display_name=ip,
            context=context,
            threat_intel_hits=ti_hits,
            risk_score=risk_score,
            risk_label=_score_to_label(risk_score),
            azure_resource_details={"resources": azure_resources},
        )

    # ── Host resolution ────────────────────────────────────────────────────────

    async def _resolve_host(self, hostname: str, kind: EntityKind) -> EntityResolutionResult:
        azure_resources = await self._resource_graph.find_resources_by_hostname(hostname)
        vm_details = await self._resource_graph.get_vm_details(hostname)

        context: dict[str, Any] = {
            "azure_resources_count": len(azure_resources),
            "is_azure_vm": vm_details is not None,
        }
        if vm_details:
            context["vm"] = vm_details

        risk_score = 4.0 if vm_details else 2.0  # Known Azure VM is a moderate risk indicator

        return EntityResolutionResult(
            entity_kind=kind,
            identifier=hostname,
            display_name=hostname,
            context=context,
            risk_score=risk_score,
            risk_label=_score_to_label(risk_score),
            azure_resource_details={"resources": azure_resources, "vm_details": vm_details},
        )

    # ── Azure Resource resolution ──────────────────────────────────────────────

    async def _resolve_azure_resource(self, resource_id: str, kind: EntityKind) -> EntityResolutionResult:
        details = await self._resource_graph.get_resource_by_id(resource_id)
        context: dict[str, Any] = {"found": details is not None}
        if details:
            context.update(details)

        return EntityResolutionResult(
            entity_kind=kind,
            identifier=resource_id,
            display_name=details.get("name", resource_id) if details else resource_id,
            context=context,
            risk_score=3.0,
            risk_label="Low",
            azure_resource_details=details or {},
        )

    # ── URL resolution ─────────────────────────────────────────────────────────

    async def _resolve_url(self, url: str, kind: EntityKind) -> EntityResolutionResult:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or url
        ti_hits = await self._ti.enrich_domain(domain)
        risk_score = ThreatIntelEnricher.aggregate_risk_score(ti_hits)
        return EntityResolutionResult(
            entity_kind=kind,
            identifier=url,
            display_name=url,
            context={"domain": domain},
            threat_intel_hits=ti_hits,
            risk_score=risk_score,
            risk_label=_score_to_label(risk_score),
        )

    # ── File hash resolution ───────────────────────────────────────────────────

    async def _resolve_hash(self, file_hash: str, kind: EntityKind) -> EntityResolutionResult:
        ti_hits = await self._ti.enrich_hash(file_hash)
        risk_score = ThreatIntelEnricher.aggregate_risk_score(ti_hits)
        return EntityResolutionResult(
            entity_kind=kind,
            identifier=file_hash,
            display_name=file_hash,
            context={"hash_length": len(file_hash)},
            threat_intel_hits=ti_hits,
            risk_score=risk_score,
            risk_label=_score_to_label(risk_score),
        )

    # ── Generic fallback ───────────────────────────────────────────────────────

    async def _resolve_generic(self, identifier: str, kind: EntityKind) -> EntityResolutionResult:
        log.warning("entity.resolve.unknown_kind", identifier=identifier, kind=kind.value)
        return EntityResolutionResult(
            entity_kind=kind,
            identifier=identifier,
            display_name=identifier,
            context={"note": "No resolver available for this entity kind"},
            risk_score=0.0,
            risk_label="Unknown",
        )


def _score_to_label(score: float) -> str:
    if score >= 8.0:
        return "Critical"
    if score >= 6.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 1.0:
        return "Low"
    return "Clean"
