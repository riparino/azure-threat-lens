"""VirusTotal threat intelligence integration."""

from __future__ import annotations

from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.threat_intel.base import ThreatIntelProvider
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import ThreatIntelHit

log = get_logger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient(ThreatIntelProvider):
    """VirusTotal v3 API client for IP, domain, and file hash lookups."""

    provider_name = "virustotal"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            api_key=cfg.threat_intel.virustotal_api_key.get_secret_value(),
            base_url=cfg.get_yaml("threat_intel", "virustotal", "base_url", default=_VT_BASE),
            timeout=cfg.get_yaml("threat_intel", "request_timeout", default=10),
        )

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key}

    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        if not self.is_available:
            log.debug("virustotal.skipped", reason="no API key")
            return None
        log.info("virustotal.lookup_ip", ip=ip)
        try:
            data = await self._get(f"ip_addresses/{ip}", headers=self._headers())
            return self._parse_response(data, identifier=ip)
        except Exception as exc:
            log.warning("virustotal.lookup_ip.failed", ip=ip, error=str(exc))
            return None

    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        log.info("virustotal.lookup_domain", domain=domain)
        try:
            data = await self._get(f"domains/{domain}", headers=self._headers())
            return self._parse_response(data, identifier=domain)
        except Exception as exc:
            log.warning("virustotal.lookup_domain.failed", domain=domain, error=str(exc))
            return None

    async def lookup_hash(self, file_hash: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        log.info("virustotal.lookup_hash", file_hash=file_hash)
        try:
            data = await self._get(f"files/{file_hash}", headers=self._headers())
            return self._parse_response(data, identifier=file_hash)
        except Exception as exc:
            log.warning("virustotal.lookup_hash.failed", hash=file_hash, error=str(exc))
            return None

    @staticmethod
    def _parse_response(data: dict[str, Any], identifier: str) -> ThreatIntelHit:
        attrs: dict[str, Any] = data.get("data", {}).get("attributes", {})
        stats: dict[str, int] = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = round((malicious + suspicious * 0.5) / total * 10, 2)
        return ThreatIntelHit(
            provider="virustotal",
            malicious=malicious > 0,
            suspicious=suspicious > 0,
            score=score,
            categories=list(attrs.get("categories", {}).values()),
            tags=attrs.get("tags", []),
            details={
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country", ""),
                "as_owner": attrs.get("as_owner", ""),
            },
        )
