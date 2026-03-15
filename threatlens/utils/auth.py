from __future__ import annotations

from azure.identity import ClientSecretCredential

from threatlens.utils.config import settings


def build_credential() -> ClientSecretCredential:
    return ClientSecretCredential(
        tenant_id=settings.azure_tenant_id,
        client_id=settings.azure_client_id,
        client_secret=settings.azure_client_secret,
    )
