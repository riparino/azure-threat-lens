from __future__ import annotations

import httpx


class AbuseIPDBClient:
    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict[str, str | int]:
        if not self.api_key:
            return {"provider": "abuseipdb", "ip": ip, "abuse_confidence_score": 0}
        async with httpx.AsyncClient(timeout=10) as client:
            _ = client
            return {"provider": "abuseipdb", "ip": ip, "abuse_confidence_score": 0}
