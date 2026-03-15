from __future__ import annotations


def get_auth_context() -> dict[str, str]:
    return {"mode": "azure-identity", "status": "configured"}
