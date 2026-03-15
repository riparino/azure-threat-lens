from __future__ import annotations


class AbuseIPDBClient:
    def enrich(self, observable: str) -> dict[str, str | int]:
        return {"provider": "abuseipdb", "observable": observable, "abuse_confidence": 0}
