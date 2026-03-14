"""Threat intelligence enrichment orchestrator.

Runs lookups across all configured providers concurrently and aggregates results.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from azure_threat_lens.integrations.threat_intel.abuseipdb import AbuseIPDBClient
from azure_threat_lens.integrations.threat_intel.base import ThreatIntelProvider
from azure_threat_lens.integrations.threat_intel.greynoise import GreyNoiseClient
from azure_threat_lens.integrations.threat_intel.virustotal import VirusTotalClient
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import ThreatIntelHit

log = get_logger(__name__)


def _is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


class ThreatIntelEnricher:
    """Orchestrates concurrent threat intelligence lookups across all providers."""

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
        """Run IP enrichment across all configured providers concurrently."""
        if not _is_public_ip(ip):
            log.debug("threat_intel.skipping_private_ip", ip=ip)
            return []

        log.info("threat_intel.enrich_ip", ip=ip, providers=self.active_providers)
        tasks = [p.lookup_ip(ip) for p in self._providers if p.is_available]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelHit)]

    async def enrich_domain(self, domain: str) -> list[ThreatIntelHit]:
        """Run domain enrichment across all configured providers concurrently."""
        log.info("threat_intel.enrich_domain", domain=domain, providers=self.active_providers)
        tasks = [p.lookup_domain(domain) for p in self._providers if p.is_available]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelHit)]

    async def enrich_hash(self, file_hash: str) -> list[ThreatIntelHit]:
        """Run file hash enrichment across all configured providers concurrently."""
        log.info("threat_intel.enrich_hash", hash=file_hash, providers=self.active_providers)
        tasks = [p.lookup_hash(file_hash) for p in self._providers if p.is_available]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelHit)]

    @staticmethod
    def aggregate_risk_score(hits: list[ThreatIntelHit]) -> float:
        """Compute a 0-10 aggregate risk score from multiple provider hits."""
        if not hits:
            return 0.0
        scores = [h.score for h in hits if h.score is not None]
        if not scores:
            malicious_count = sum(1 for h in hits if h.malicious)
            return min(malicious_count * 3.0, 10.0)
        # Weight: highest score + average of the rest
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        return round(max_score * 0.7 + avg_score * 0.3, 2)
