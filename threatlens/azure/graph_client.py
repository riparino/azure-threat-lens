from __future__ import annotations


class GraphClient:
    def get_identity(self, identity: str) -> dict[str, str | bool]:
        return {
            "identity": identity,
            "accountEnabled": True,
            "mfaRegistered": True,
            "riskLevel": "medium",
        }
