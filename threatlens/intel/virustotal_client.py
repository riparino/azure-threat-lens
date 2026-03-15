from __future__ import annotations


class VirusTotalClient:
    def enrich(self, observable: str) -> dict[str, str | int]:
        return {"provider": "virustotal", "observable": observable, "score": 0}
