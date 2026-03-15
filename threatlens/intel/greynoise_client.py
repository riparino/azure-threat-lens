from __future__ import annotations


class GreyNoiseClient:
    def enrich(self, observable: str) -> dict[str, str | bool]:
        return {"provider": "greynoise", "observable": observable, "noise": False}
