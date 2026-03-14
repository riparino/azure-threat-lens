"""Application settings loaded from environment variables and YAML config."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AzureSettings(BaseSettings):
    tenant_id: str = Field("", alias="ATL_AZURE_TENANT_ID")
    client_id: str = Field("", alias="ATL_AZURE_CLIENT_ID")
    client_secret: SecretStr = Field(SecretStr(""), alias="ATL_AZURE_CLIENT_SECRET")
    subscription_id: str = Field("", alias="ATL_AZURE_SUBSCRIPTION_ID")

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class LighthouseWorkspace(BaseSettings):
    """Configuration for a single Sentinel workspace (used in Lighthouse multi-tenant mode)."""

    workspace_id: str
    workspace_name: str
    resource_group: str
    subscription_id: str
    tenant_id: str = ""  # Delegated tenant; falls back to primary if empty
    display_name: str = ""

    model_config = SettingsConfigDict(populate_by_name=True)


class SentinelSettings(BaseSettings):
    # ── Primary / default workspace ────────────────────────────────────────────
    workspace_id: str = Field("", alias="ATL_SENTINEL_WORKSPACE_ID")
    workspace_name: str = Field("", alias="ATL_SENTINEL_WORKSPACE_NAME")
    resource_group: str = Field("", alias="ATL_SENTINEL_RESOURCE_GROUP")
    api_version: str = "2023-11-01"
    default_lookback_hours: int = 72
    max_incidents: int = 100

    # ── Azure Lighthouse multi-workspace support ───────────────────────────────
    # Supply a JSON-encoded list of LighthouseWorkspace dicts via the env var:
    #   ATL_SENTINEL_WORKSPACES='[{"workspace_id":"...","workspace_name":"...","resource_group":"...","subscription_id":"..."}]'
    # When set, the CLI --workspace flag can target any of these workspaces by
    # workspace_name. The primary workspace above is always included as default.
    lighthouse_workspaces: list[LighthouseWorkspace] = Field(
        default_factory=list,
        alias="ATL_SENTINEL_WORKSPACES",
    )

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")

    def all_workspaces(self, subscription_id: str = "") -> list[LighthouseWorkspace]:
        """Return all workspaces including the primary, de-duplicated by workspace_id."""
        workspaces: list[LighthouseWorkspace] = []
        if self.workspace_id or self.workspace_name:
            workspaces.append(
                LighthouseWorkspace(
                    workspace_id=self.workspace_id,
                    workspace_name=self.workspace_name,
                    resource_group=self.resource_group,
                    subscription_id=subscription_id,
                    display_name=self.workspace_name or "Primary",
                )
            )
        seen = {self.workspace_id}
        for ws in self.lighthouse_workspaces:
            if ws.workspace_id not in seen:
                workspaces.append(ws)
                seen.add(ws.workspace_id)
        return workspaces

    def get_workspace(self, name_or_id: str, subscription_id: str = "") -> LighthouseWorkspace | None:
        """Look up a workspace by display name or workspace_id."""
        for ws in self.all_workspaces(subscription_id):
            if ws.workspace_name == name_or_id or ws.workspace_id == name_or_id or ws.display_name == name_or_id:
                return ws
        return None


class DefenderSettings(BaseSettings):
    enabled: bool = Field(False, alias="ATL_DEFENDER_ENABLED")
    tenant_id: str = Field("", alias="ATL_DEFENDER_TENANT_ID")
    api_version: str = "2024-02-15"

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class LLMSettings(BaseSettings):
    api_key: SecretStr = Field(SecretStr(""), alias="ATL_ANTHROPIC_API_KEY")
    model: str = Field("claude-sonnet-4-6", alias="ATL_LLM_MODEL")
    max_tokens: int = Field(4096, alias="ATL_LLM_MAX_TOKENS")
    temperature: float = 0.2

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class ThreatIntelSettings(BaseSettings):
    virustotal_api_key: SecretStr = Field(SecretStr(""), alias="ATL_VIRUSTOTAL_API_KEY")
    greynoise_api_key: SecretStr = Field(SecretStr(""), alias="ATL_GREYNOISE_API_KEY")
    abuseipdb_api_key: SecretStr = Field(SecretStr(""), alias="ATL_ABUSEIPDB_API_KEY")

    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.virustotal_api_key.get_secret_value())

    @property
    def greynoise_enabled(self) -> bool:
        return bool(self.greynoise_api_key.get_secret_value())

    @property
    def abuseipdb_enabled(self) -> bool:
        return bool(self.abuseipdb_api_key.get_secret_value())

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class AppSettings(BaseSettings):
    log_level: str = Field("INFO", alias="ATL_LOG_LEVEL")
    log_format: str = Field("console", alias="ATL_LOG_FORMAT")
    output_format: str = Field("rich", alias="ATL_OUTPUT_FORMAT")
    config_file: str = Field("config/default.yaml", alias="ATL_CONFIG_FILE")

    # Nested settings
    azure: AzureSettings = Field(default_factory=AzureSettings)
    sentinel: SentinelSettings = Field(default_factory=SentinelSettings)
    defender: DefenderSettings = Field(default_factory=DefenderSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)

    # Extra config loaded from YAML (merged at runtime)
    _yaml_config: dict[str, Any] = {}

    model_config = SettingsConfigDict(
        populate_by_name=True,
        env_file=".env",
        env_nested_delimiter="__",
    )

    @model_validator(mode="after")
    def load_yaml_config(self) -> "AppSettings":
        config_path = Path(self.config_file)
        if config_path.exists():
            with config_path.open() as fh:
                self._yaml_config = yaml.safe_load(fh) or {}
        return self

    def get_yaml(self, *keys: str, default: Any = None) -> Any:
        """Navigate nested YAML config: get_yaml('sentinel', 'max_incidents')."""
        node: Any = self._yaml_config
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key, default)
        return node

    @property
    def is_llm_configured(self) -> bool:
        return bool(self.llm.api_key.get_secret_value())

    @property
    def is_azure_configured(self) -> bool:
        return bool(self.azure.tenant_id and self.azure.client_id)


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Return a cached singleton settings instance."""
    return AppSettings()


def reload_settings() -> AppSettings:
    """Clear cache and reload settings (useful for testing)."""
    get_settings.cache_clear()
    return get_settings()
