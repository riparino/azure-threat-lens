from __future__ import annotations


def analyze_token_abuse(identity: str) -> list[str]:
    if identity.endswith("@contoso.com"):
        return ["Legacy auth tokens should be revoked and re-issued"]
    return ["Review OAuth app consent grants for suspicious scopes"]
