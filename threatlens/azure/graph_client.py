from __future__ import annotations

from typing import Any


class GraphClient:
    async def get_identity_profile(self, identity: str) -> dict[str, Any]:
        return {
            "identity": identity,
            "mfa_enabled": False,
            "recent_failed_signins": 9,
            "risk_level": "high",
        }
