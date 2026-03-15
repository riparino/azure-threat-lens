"""Network entity resolver – IPs, hostnames, URLs, file hashes."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from threatlens.entities.entity_resolver import score_to_label
from threatlens.intel.enricher import ThreatIntelEnricher
from threatlens.models.entities import EntityKind, ResolvedEntity
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class NetworkResolver:
    """Resolves IP addresses, hostnames, URLs, and file hashes."""

    def __init__(self) -> None:
        self._ti = ThreatIntelEnricher()
        from threatlens.azure.resource_graph_client import ResourceGraphClient
        self._rg = ResourceGraphClient()

    async def resolve_ip(self, ip: str) -> ResolvedEntity:
        """Resolve an IP address: threat intel + Azure resource lookup."""
        ti_hits = await self._ti.enrich_ip(ip)
        azure_resources = await self._rg.find_by_ip(ip)
        risk_score = ThreatIntelEnricher.aggregate_risk_score(ti_hits)

        try:
            addr = ipaddress.ip_address(ip)
            is_private = addr.is_private
        except ValueError:
            is_private = False

        context = {
            "is_private": is_private,
            "azure_resources_found": len(azure_resources),
        }
        if ti_hits:
            context["threat_intel"] = {
                h.provider: {"malicious": h.malicious, "score": h.score}
                for h in ti_hits
            }

        indicators = []
        for hit in ti_hits:
            if hit.malicious:
                indicators.append(f"Flagged malicious by {hit.provider}")
            elif hit.suspicious:
                indicators.append(f"Flagged suspicious by {hit.provider}")
        if azure_resources:
            indicators.append(f"Associated with {len(azure_resources)} Azure resource(s)")

        return ResolvedEntity(
            entity_kind=EntityKind.IP,
            identifier=ip,
            display_name=ip,
            context=context,
            threat_intel_hits=ti_hits,
            risk_score=risk_score,
            risk_label=score_to_label(risk_score),
            risk_indicators=indicators,
            azure_resource_details={"resources": azure_resources},
        )

    async def resolve_host(self, hostname: str) -> ResolvedEntity:
        """Resolve a hostname: Azure resource lookup + basic risk assessment."""
        azure_resources = await self._rg.find_by_hostname(hostname)
        vm_details = await self._rg.get_vm_details(hostname)

        context = {
            "azure_resources_found": len(azure_resources),
            "is_azure_vm": vm_details is not None,
        }
        if vm_details:
            context["vm"] = vm_details

        indicators = []
        if vm_details:
            indicators.append(f"Azure VM identified: {vm_details.get('sku', 'Unknown SKU')}")
        if len(azure_resources) > 1:
            indicators.append(f"Multiple Azure resources associated ({len(azure_resources)})")

        return ResolvedEntity(
            entity_kind=EntityKind.HOST,
            identifier=hostname,
            display_name=hostname,
            context=context,
            risk_score=4.0 if vm_details else 2.0,
            risk_label="Medium" if vm_details else "Low",
            risk_indicators=indicators,
            azure_resource_details={"resources": azure_resources, "vm_details": vm_details},
        )

    async def resolve_url(self, url: str) -> ResolvedEntity:
        """Resolve a URL: domain threat intel lookup."""
        parsed = urlparse(url)
        domain = parsed.netloc or url
        ti_hits = await self._ti.enrich_domain(domain)
        risk_score = ThreatIntelEnricher.aggregate_risk_score(ti_hits)

        indicators = [
            f"Domain {domain} flagged by {h.provider}"
            for h in ti_hits if h.malicious
        ]

        return ResolvedEntity(
            entity_kind=EntityKind.URL,
            identifier=url,
            display_name=url,
            context={"domain": domain},
            threat_intel_hits=ti_hits,
            risk_score=risk_score,
            risk_label=score_to_label(risk_score),
            risk_indicators=indicators,
        )

    async def resolve_hash(self, file_hash: str) -> ResolvedEntity:
        """Resolve a file hash: threat intel lookup."""
        ti_hits = await self._ti.enrich_hash(file_hash)
        risk_score = ThreatIntelEnricher.aggregate_risk_score(ti_hits)

        indicators = [
            f"Hash flagged malicious by {h.provider}"
            for h in ti_hits if h.malicious
        ]

        return ResolvedEntity(
            entity_kind=EntityKind.FILE_HASH,
            identifier=file_hash,
            display_name=file_hash[:16] + "...",
            context={"hash_length": len(file_hash)},
            threat_intel_hits=ti_hits,
            risk_score=risk_score,
            risk_label=score_to_label(risk_score),
            risk_indicators=indicators,
        )
