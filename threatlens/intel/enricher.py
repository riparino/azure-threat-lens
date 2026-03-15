from __future__ import annotations

from threatlens.intel.abuseipdb_client import AbuseIPDBClient
from threatlens.intel.greynoise_client import GreyNoiseClient
from threatlens.intel.virustotal_client import VirusTotalClient


class ThreatIntelEnricher:
    def __init__(self) -> None:
        self._providers = [VirusTotalClient(), GreyNoiseClient(), AbuseIPDBClient()]

    def enrich(self, observable: str) -> list[dict[str, object]]:
        return [provider.enrich(observable) for provider in self._providers]
