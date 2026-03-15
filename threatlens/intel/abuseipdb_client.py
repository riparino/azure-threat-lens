"""AbuseIPDB v2 API client."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from threatlens.intel._base import ThreatIntelProvider
from threatlens.models.entities import ThreatIntelHit
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_CATEGORIES: dict[int, str] = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


class AbuseIPDBClient(ThreatIntelProvider):
    provider_name = "abuseipdb"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            api_key=cfg.threat_intel.abuseipdb_api_key.get_secret_value(),
            base_url=cfg.get_yaml("threat_intel", "abuseipdb", "base_url", default="https://api.abuseipdb.com/api/v2"),
            timeout=cfg.get_yaml("threat_intel", "request_timeout", default=10),
        )

    def _h(self) -> dict[str, str]:
        return {"Key": self._api_key, "Accept": "application/json"}

    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        if not self.is_available:
            return None
        log.info("abuseipdb.lookup_ip", ip=ip)
        try:
            data = await self._get("check", headers=self._h(),
                                   params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
            return self._parse(data)
        except Exception as exc:
            log.warning("abuseipdb.lookup_ip.failed", ip=ip, error=str(exc))
            return None

    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        return None

    @staticmethod
    def _parse(data: dict[str, Any]) -> ThreatIntelHit:
        attrs = data.get("data", {})
        score_pct: int = attrs.get("abuseConfidenceScore", 0)
        categories: list[str] = []
        for report in attrs.get("reports", [])[:5]:
            for cat in report.get("categories", []):
                name = _CATEGORIES.get(cat, str(cat))
                if name not in categories:
                    categories.append(name)
        last_seen: datetime | None = None
        if raw_ts := attrs.get("lastReportedAt"):
            try:
                last_seen = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return ThreatIntelHit(
            provider="abuseipdb",
            malicious=score_pct >= 80,
            suspicious=score_pct >= 25,
            score=round(score_pct / 10, 1),
            categories=categories,
            last_seen=last_seen,
            details={"abuse_confidence_score": score_pct,
                     "total_reports": attrs.get("totalReports", 0),
                     "country_code": attrs.get("countryCode", ""),
                     "isp": attrs.get("isp", ""),
                     "is_tor": attrs.get("isTor", False)},
        )
