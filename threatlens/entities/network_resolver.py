from __future__ import annotations

from threatlens.intel.abuseipdb_client import AbuseIPDBClient
from threatlens.intel.greynoise_client import GreyNoiseClient
from threatlens.intel.virustotal_client import VirusTotalClient


class NetworkResolver:
    def __init__(
        self,
        virustotal_client: VirusTotalClient,
        greynoise_client: GreyNoiseClient,
        abuseipdb_client: AbuseIPDBClient,
    ) -> None:
        self.virustotal_client = virustotal_client
        self.greynoise_client = greynoise_client
        self.abuseipdb_client = abuseipdb_client

    async def resolve_ip(self, ip: str) -> dict[str, object]:
        vt = await self.virustotal_client.lookup_ip(ip)
        gn = await self.greynoise_client.lookup_ip(ip)
        abuse = await self.abuseipdb_client.lookup_ip(ip)
        return {"ip": ip, "virustotal": vt, "greynoise": gn, "abuseipdb": abuse}
