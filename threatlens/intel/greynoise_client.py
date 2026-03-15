"""GreyNoise v3 API client."""

from __future__ import annotations

from typing import Any

from threatlens.intel._base import ThreatIntelProvider
from threatlens.models.entities import ThreatIntelHit
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class GreyNoiseClient(ThreatIntelProvider):
    provider_name = "greynoise"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            api_key=cfg.threat_intel.greynoise_api_key.get_secret_value(),
            base_url=cfg.get_yaml("threat_intel", "greynoise", "base_url", default="https://api.greynoise.io/v3"),
            timeout=cfg.get_yaml("threat_intel", "request_timeout", default=10),
        )

    def _h(self) -> dict[str, str]:
        return {"key": self._api_key, "Accept": "application/json"}

    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        log.info("greynoise.lookup_ip", ip=ip)
        try:
            return self._parse(await self._get(f"community/{ip}", headers=self._h()))
        except Exception as exc:
            log.warning("greynoise.lookup_ip.failed", ip=ip, error=str(exc))
            return None

    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        return None  # GreyNoise is IP-centric

    @staticmethod
    def _parse(data: dict[str, Any]) -> ThreatIntelHit:
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        cls = data.get("classification", "unknown")
        score_map = {"malicious": 8.5, "unknown": 3.0, "benign": 0.5}
        return ThreatIntelHit(
            provider="greynoise",
            malicious=cls == "malicious",
            suspicious=noise and not riot and cls not in ("benign",),
            score=score_map.get(cls, 3.0),
            tags=[data.get("name", "")] if data.get("name") else [],
            details={"noise": noise, "riot": riot, "classification": cls,
                     "message": data.get("message", ""), "link": data.get("link", "")},
        )
