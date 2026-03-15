from __future__ import annotations

import httpx


class GreyNoiseClient:
    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict[str, str]:
        if not self.api_key:
            return {"provider": "greynoise", "ip": ip, "classification": "unknown"}
        async with httpx.AsyncClient(timeout=10) as client:
            _ = client
            return {"provider": "greynoise", "ip": ip, "classification": "unknown"}
