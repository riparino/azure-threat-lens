"""Azure authentication helpers.

Provides a centralised credential factory so all Azure clients use a consistent
authentication strategy (service principal, DefaultAzureCredential, or workload
identity depending on the environment).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import SecretStr

from threatlens.utils.logging import get_logger

log = get_logger(__name__)


def build_credential(
    tenant_id: str,
    client_id: str,
    client_secret: SecretStr | str,
) -> Any:
    """Return an azure-identity credential object.

    Uses ``ClientSecretCredential`` when a complete service-principal triple is
    provided; falls back to ``DefaultAzureCredential`` (which covers managed
    identity, Azure CLI, environment variables, etc.) otherwise.

    The import of ``azure.identity`` is deferred to this function so that the
    rest of the package can be imported without a working ``azure-identity``
    installation.
    """
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential  # noqa: PLC0415
    except Exception as exc:
        raise ImportError(
            "azure-identity is required. Install it with: pip install azure-identity"
        ) from exc

    secret = (
        client_secret.get_secret_value()
        if isinstance(client_secret, SecretStr)
        else client_secret
    )

    if tenant_id and client_id and secret:
        log.debug("auth.using_service_principal", client_id=client_id)
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=secret,
        )

    log.debug("auth.using_default_credential")
    return DefaultAzureCredential()


def get_token(credential: Any, *scopes: str) -> str:
    """Acquire a bearer token from an azure-identity credential."""
    token = credential.get_token(*scopes)
    return token.token  # type: ignore[no-any-return]
