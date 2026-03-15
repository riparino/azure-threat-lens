"""Base Azure API client with authentication and retry logic."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from pydantic import SecretStr

from azure_threat_lens.logging import get_logger

log = get_logger(__name__)


class AzureClientError(Exception):
    """Raised when an Azure API call fails."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class BaseAzureClient:
    """Shared async HTTP client for Azure REST APIs.

    Handles token acquisition, retry with exponential backoff, and
    consistent error raising so callers can focus on business logic.
    """

    RETRYABLE_STATUS = {429, 500, 502, 503, 504}

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: SecretStr | str,
        scopes: list[str],
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        secret = (
            client_secret.get_secret_value()
            if isinstance(client_secret, SecretStr)
            else client_secret
        )
        # Lazy import azure.identity so modules can be imported without
        # requiring azure-identity to be installed or functioning at module load.
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential  # noqa: PLC0415
        except Exception as exc:  # pragma: no cover
            raise ImportError(
                "azure-identity is required to use Azure API clients. "
                "Install it with: pip install azure-identity"
            ) from exc
        if tenant_id and client_id and secret:
            self._credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=secret,
            )
            log.debug("azure_client.using_service_principal", client_id=client_id)
        else:
            self._credential = DefaultAzureCredential()
            log.debug("azure_client.using_default_credential")

        self._scopes = scopes
        self._timeout = timeout
        self._max_retries = max_retries
        self._http: httpx.AsyncClient | None = None

    async def _get_token(self) -> str:
        token = self._credential.get_token(*self._scopes)
        return token.token

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            token = await self._get_token()
            self._http = httpx.AsyncClient(
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=self._timeout,
            )
        return self._http

    async def _refresh_token(self) -> None:
        """Re-acquire a token and update the Authorization header."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
        self._http = None

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                client = await self._client()
                resp = await client.request(method, url, params=params, json=json)

                if resp.status_code == 401:
                    log.debug("azure_client.token_expired", attempt=attempt)
                    await self._refresh_token()
                    continue

                if resp.status_code in self.RETRYABLE_STATUS:
                    wait = 2 ** attempt
                    log.warning(
                        "azure_client.retrying",
                        status=resp.status_code,
                        attempt=attempt,
                        wait=wait,
                    )
                    await asyncio.sleep(wait)
                    last_exc = AzureClientError(
                        f"HTTP {resp.status_code} from {url}",
                        status_code=resp.status_code,
                        response_body=resp.text,
                    )
                    continue

                if resp.status_code >= 400:
                    raise AzureClientError(
                        f"HTTP {resp.status_code} from {url}: {resp.text[:500]}",
                        status_code=resp.status_code,
                        response_body=resp.text,
                    )

                return resp.json()  # type: ignore[no-any-return]

            except httpx.RequestError as exc:
                wait = 2 ** attempt
                log.warning("azure_client.network_error", error=str(exc), attempt=attempt, wait=wait)
                await asyncio.sleep(wait)
                last_exc = exc

        raise AzureClientError(f"All retries exhausted for {url}") from last_exc

    async def get(self, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> dict[str, Any] | list[Any]:
        return await self._request("POST", url, **kwargs)

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    async def __aenter__(self) -> "BaseAzureClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
