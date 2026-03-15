"""Abstract base class for threat intelligence providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from azure_threat_lens.logging import get_logger
from azure_threat_lens.models.entity import ThreatIntelHit

log = get_logger(__name__)


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence enrichment providers."""

    provider_name: str = "unknown"

    def __init__(self, api_key: str, base_url: str, timeout: float = 10.0) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    @abstractmethod
    async def lookup_ip(self, ip: str) -> ThreatIntelHit | None:
        """Look up an IP address and return a ThreatIntelHit or None."""

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ThreatIntelHit | None:
        """Look up a domain and return a ThreatIntelHit or None."""

    async def lookup_hash(self, file_hash: str) -> ThreatIntelHit | None:
        """Look up a file hash – not all providers support this; default to None."""
        return None

    async def _get(self, path: str, *, headers: dict[str, str] | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self._base_url}/{path.lstrip('/')}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(url, headers=headers or {}, params=params or {})
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
