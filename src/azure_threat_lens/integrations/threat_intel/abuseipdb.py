"""AbuseIPDB threat intelligence integration."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.threat_intel.base import ThreatIntelProvider
from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import ThreatIntelHit

log = get_logger(__name__)

_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient(ThreatIntelProvider):
    """AbuseIPDB v2 client – community-sourced IP abuse confidence scores."""

    provider_name = "abuseipdb"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            api_key=cfg.threat_intel.abuseipdb_api_key.get_secret_value(),
            base_url=cfg.get_yaml("threat_intel", "abuseipdb", "base_url", default=_ABUSEIPDB_BASE),
            timeout=cfg.get_yaml("threat_intel", "request_timeout", default=10),
        )

    def _headers(self) -> dict[str, str]:
        return {"Key": self._api_key, "Accept": "application/json"}

    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        if not self.is_available:
            log.debug("abuseipdb.skipped", reason="no API key")
            return None
        log.info("abuseipdb.lookup_ip", ip=ip)
        try:
            data = await self._get(
                "check",
                headers=self._headers(),
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )
            return self._parse_response(data)
        except Exception as exc:
            log.warning("abuseipdb.lookup_ip.failed", ip=ip, error=str(exc))
            return None

    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        # AbuseIPDB is IP-centric
        return None

    @staticmethod
    def _parse_response(data: dict[str, Any]) -> ThreatIntelHit:
        attrs: dict[str, Any] = data.get("data", {})
        score_pct: int = attrs.get("abuseConfidenceScore", 0)
        score = round(score_pct / 10, 1)
        reports: list[dict[str, Any]] = attrs.get("reports", [])
        categories: list[str] = []
        for report in reports[:5]:
            for cat in report.get("categories", []):
                cat_name = _ABUSE_CATEGORIES.get(cat, str(cat))
                if cat_name not in categories:
                    categories.append(cat_name)

        last_seen_str: str | None = attrs.get("lastReportedAt")
        last_seen: datetime | None = None
        if last_seen_str:
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        return ThreatIntelHit(
            provider="abuseipdb",
            malicious=score_pct >= 80,
            suspicious=score_pct >= 25,
            score=score,
            categories=categories,
            last_seen=last_seen,
            details={
                "abuse_confidence_score": score_pct,
                "total_reports": attrs.get("totalReports", 0),
                "country_code": attrs.get("countryCode", ""),
                "usage_type": attrs.get("usageType", ""),
                "isp": attrs.get("isp", ""),
                "domain": attrs.get("domain", ""),
                "is_tor": attrs.get("isTor", False),
            },
        )


# AbuseIPDB category codes → human-readable names
_ABUSE_CATEGORIES: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}
