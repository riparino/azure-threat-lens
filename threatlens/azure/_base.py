"""Base Azure REST API client with token management and retry logic."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from pydantic import SecretStr

from threatlens.utils.auth import build_credential, get_token
from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class AzureClientError(Exception):
    def __init__(self, message: str, status_code: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class BaseAzureClient:
    """Shared async HTTP client for Azure ARM/Graph/Security APIs."""

    RETRYABLE = {429, 500, 502, 503, 504}

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: SecretStr | str,
        scopes: list[str],
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._credential = build_credential(tenant_id, client_id, client_secret)
        self._scopes = scopes
        self._timeout = timeout
        self._max_retries = max_retries
        self._http: httpx.AsyncClient | None = None

    async def _bearer_token(self) -> str:
        return get_token(self._credential, *self._scopes)

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            token = await self._bearer_token()
            self._http = httpx.AsyncClient(
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=self._timeout,
            )
        return self._http

    async def _reset_client(self) -> None:
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
                    await self._reset_client()
                    continue
                if resp.status_code in self.RETRYABLE:
                    wait = 2 ** attempt
                    log.warning("azure.retrying", status=resp.status_code, wait=wait, url=url)
                    await asyncio.sleep(wait)
                    last_exc = AzureClientError(f"HTTP {resp.status_code}", resp.status_code, resp.text)
                    continue
                if resp.status_code >= 400:
                    raise AzureClientError(
                        f"HTTP {resp.status_code}: {resp.text[:400]}", resp.status_code, resp.text
                    )
                return resp.json()  # type: ignore[no-any-return]
            except httpx.RequestError as exc:
                wait = 2 ** attempt
                log.warning("azure.network_error", error=str(exc), wait=wait)
                await asyncio.sleep(wait)
                last_exc = exc
        raise AzureClientError(f"All retries exhausted for {url}") from last_exc

    async def get(self, url: str, **kw: Any) -> dict[str, Any] | list[Any]:
        return await self._request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> dict[str, Any] | list[Any]:
        return await self._request("POST", url, **kw)

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    async def __aenter__(self) -> "BaseAzureClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
