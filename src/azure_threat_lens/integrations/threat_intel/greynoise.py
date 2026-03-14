"""GreyNoise threat intelligence integration."""

from __future__ import annotations

from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.threat_intel.base import ThreatIntelProvider
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import ThreatIntelHit

log = get_logger(__name__)

_GN_BASE = "https://api.greynoise.io/v3"


class GreyNoiseClient(ThreatIntelProvider):
    """GreyNoise v3 API client – identifies noisy / benign internet scanners."""

    provider_name = "greynoise"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            api_key=cfg.threat_intel.greynoise_api_key.get_secret_value(),
            base_url=cfg.get_yaml("threat_intel", "greynoise", "base_url", default=_GN_BASE),
            timeout=cfg.get_yaml("threat_intel", "request_timeout", default=10),
        )

    def _headers(self) -> dict[str, str]:
        return {"key": self._api_key, "Accept": "application/json"}

    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        if not self.is_available:
            log.debug("greynoise.skipped", reason="no API key")
            return None
        log.info("greynoise.lookup_ip", ip=ip)
        try:
            data = await self._get(f"community/{ip}", headers=self._headers())
            return self._parse_community(data, ip)
        except Exception as exc:
            log.warning("greynoise.lookup_ip.failed", ip=ip, error=str(exc))
            return None

    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        # GreyNoise is IP-centric; domain lookups not directly supported
        return None

    @staticmethod
    def _parse_community(data: dict[str, Any], ip: str) -> ThreatIntelHit:
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")
        malicious = classification == "malicious"
        suspicious = noise and not riot and classification not in ("benign",)
        score_map = {"malicious": 8.5, "unknown": 3.0, "benign": 0.5}
        score = score_map.get(classification, 3.0)
        return ThreatIntelHit(
            provider="greynoise",
            malicious=malicious,
            suspicious=suspicious,
            score=score,
            tags=[data.get("name", "")] if data.get("name") else [],
            details={
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "message": data.get("message", ""),
                "link": data.get("link", ""),
            },
        )
