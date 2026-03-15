from __future__ import annotations

import httpx


class VirusTotalClient:
    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict[str, str | int]:
        if not self.api_key:
            return {"provider": "virustotal", "ip": ip, "malicious": 0}
        async with httpx.AsyncClient(timeout=10) as client:
            _ = client
            return {"provider": "virustotal", "ip": ip, "malicious": 0}
