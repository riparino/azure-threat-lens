"""VirusTotal v3 API client."""

from __future__ import annotations

from typing import Any

from threatlens.intel._base import ThreatIntelProvider
from threatlens.models.entities import ThreatIntelHit
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class VirusTotalClient(ThreatIntelProvider):
    provider_name = "virustotal"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            api_key=cfg.threat_intel.virustotal_api_key.get_secret_value(),
            base_url=cfg.get_yaml("threat_intel", "virustotal", "base_url", default="https://www.virustotal.com/api/v3"),
            timeout=cfg.get_yaml("threat_intel", "request_timeout", default=10),
        )

    def _h(self) -> dict[str, str]:
        return {"x-apikey": self._api_key}

    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        log.info("virustotal.lookup_ip", ip=ip)
        try:
            return self._parse(await self._get(f"ip_addresses/{ip}", headers=self._h()))
        except Exception as exc:
            log.warning("virustotal.lookup_ip.failed", ip=ip, error=str(exc))
            return None

    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        try:
            return self._parse(await self._get(f"domains/{domain}", headers=self._h()))
        except Exception as exc:
            log.warning("virustotal.lookup_domain.failed", domain=domain, error=str(exc))
            return None

    async def lookup_hash(self, file_hash: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        try:
            return self._parse(await self._get(f"files/{file_hash}", headers=self._h()))
        except Exception as exc:
            log.warning("virustotal.lookup_hash.failed", hash=file_hash, error=str(exc))
            return None

    @staticmethod
    def _parse(data: dict[str, Any]) -> ThreatIntelHit:
        attrs = data.get("data", {}).get("attributes", {})
        stats: dict[str, int] = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        return ThreatIntelHit(
            provider="virustotal",
            malicious=mal > 0,
            suspicious=sus > 0,
            score=round((mal + sus * 0.5) / total * 10, 2),
            categories=list(attrs.get("categories", {}).values()),
            tags=attrs.get("tags", []),
            details={"malicious": mal, "suspicious": sus, "total": total,
                     "reputation": attrs.get("reputation", 0),
                     "country": attrs.get("country", ""),
                     "as_owner": attrs.get("as_owner", "")},
        )
