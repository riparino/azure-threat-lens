"""Threat intelligence enrichment – runs all providers concurrently."""

from __future__ import annotations

import asyncio
import ipaddress

from threatlens.intel._base import ThreatIntelProvider
from threatlens.intel.abuseipdb_client import AbuseIPDBClient
from threatlens.intel.greynoise_client import GreyNoiseClient
from threatlens.intel.virustotal_client import VirusTotalClient
from threatlens.models.entities import ThreatIntelHit
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


def is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


class ThreatIntelEnricher:
    """Concurrent threat intelligence enrichment across all configured providers."""

    def __init__(self) -> None:
        self._providers: list[ThreatIntelProvider] = [
            VirusTotalClient(),
            GreyNoiseClient(),
            AbuseIPDBClient(),
        ]

    @property
    def active_providers(self) -> list[str]:
        return [p.provider_name for p in self._providers if p.is_available]

    async def enrich_ip(self, ip: str) -> list[ThreatIntelHit]:
        if not is_public_ip(ip):
            return []
        tasks = [p.lookup_ip(ip) for p in self._providers if p.is_available]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelHit)]

    async def enrich_domain(self, domain: str) -> list[ThreatIntelHit]:
        tasks = [p.lookup_domain(domain) for p in self._providers if p.is_available]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelHit)]

    async def enrich_hash(self, file_hash: str) -> list[ThreatIntelHit]:
        tasks = [p.lookup_hash(file_hash) for p in self._providers if p.is_available]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelHit)]

    @staticmethod
    def aggregate_risk_score(hits: list[ThreatIntelHit]) -> float:
        if not hits:
            return 0.0
        scores = [h.score for h in hits if h.score is not None]
        if not scores:
            return min(sum(1 for h in hits if h.malicious) * 3.0, 10.0)
        return round(max(scores) * 0.7 + (sum(scores) / len(scores)) * 0.3, 2)
