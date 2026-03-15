"""Azure OpenAI LLM engine – uses Entra ID authentication (no API key).

Authentication flow:
  1. Acquire a token from Entra ID using DefaultAzureCredential or ClientSecretCredential
  2. Pass the token as a Bearer token to the Azure OpenAI endpoint
  3. The openai SDK handles the HTTP calls; we supply a token_provider callable

Environment variables required:
  ATL_LLM_ENDPOINT    – Azure OpenAI endpoint, e.g. https://<resource>.openai.azure.com/
  ATL_LLM_DEPLOYMENT  – Deployment name, e.g. gpt-4o
  ATL_LLM_API_VERSION – API version, e.g. 2024-02-01 (default provided)
"""

from __future__ import annotations

import asyncio
from typing import Any

from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_AZURE_OPENAI_SCOPE = "https://cognitiveservices.azure.com/.default"
_DEFAULT_API_VERSION = "2024-02-01"


class LLMEngine:
    """Wraps Azure OpenAI with Entra ID token-based authentication."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._endpoint = cfg.llm.endpoint
        self._deployment = cfg.llm.deployment
        self._api_version = cfg.llm.api_version or _DEFAULT_API_VERSION
        self._max_tokens = cfg.llm.max_tokens
        self._temperature = cfg.llm.temperature
        self._enabled = bool(self._endpoint and self._deployment)
        self._client: Any = None  # lazy-initialised on first use

    def _get_client(self) -> Any:
        """Lazily build the AzureOpenAI async client with Entra token provider."""
        if self._client is not None:
            return self._client

        try:
            from openai import AsyncAzureOpenAI  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "openai package is required for LLM support. "
                "Install it with: pip install openai>=1.0"
            ) from exc

        from threatlens.utils.auth import build_credential

        cfg = get_settings()
        credential = build_credential(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
        )

        def _token_provider() -> str:
            """Synchronous token provider called by the openai SDK."""
            from threatlens.utils.auth import get_token
            return get_token(credential, _AZURE_OPENAI_SCOPE)

        self._client = AsyncAzureOpenAI(
            azure_endpoint=self._endpoint,
            azure_deployment=self._deployment,
            api_version=self._api_version,
            azure_ad_token_provider=_token_provider,
            # Explicitly do NOT set api_key – Entra auth only
        )
        return self._client

    async def complete(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """Send a completion request and return the assistant message text.

        Falls back to a placeholder message if the LLM is not configured.
        """
        if not self._enabled:
            log.warning("llm_engine.not_configured")
            return (
                "[LLM analysis unavailable – set ATL_LLM_ENDPOINT and "
                "ATL_LLM_DEPLOYMENT to enable Azure OpenAI enrichment]"
            )

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            client = self._get_client()
            response = await client.chat.completions.create(
                model=self._deployment,
                messages=messages,
                max_tokens=max_tokens or self._max_tokens,
                temperature=temperature if temperature is not None else self._temperature,
            )
            content = response.choices[0].message.content or ""
            log.info(
                "llm_engine.complete",
                tokens_used=response.usage.total_tokens if response.usage else None,
            )
            return content
        except Exception as exc:
            log.error("llm_engine.complete.failed", error=str(exc))
            raise

    async def complete_structured(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        """Request a JSON-mode completion.

        Pass response_format={"type": "json_object"} to guarantee JSON output.
        """
        if not self._enabled:
            return '{"error": "LLM not configured"}'

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            client = self._get_client()
            kwargs: dict[str, Any] = {
                "model": self._deployment,
                "messages": messages,
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
            }
            if response_format:
                kwargs["response_format"] = response_format

            response = await client.chat.completions.create(**kwargs)
            return response.choices[0].message.content or "{}"
        except Exception as exc:
            log.error("llm_engine.complete_structured.failed", error=str(exc))
            raise

    async def summarise(self, text: str, *, max_words: int = 150) -> str:
        """Generate a concise summary of provided text."""
        prompt = (
            f"Summarise the following security investigation findings in plain English, "
            f"in no more than {max_words} words. Focus on the most important risk indicators "
            f"and recommended actions.\n\n{text}"
        )
        return await self.complete(
            prompt,
            system_prompt=(
                "You are a senior SOC analyst summarising Azure security investigation results. "
                "Be concise, factual, and avoid repeating information."
            ),
        )
