"""Application configuration – loaded from environment variables and YAML.

Priority order (highest wins): environment variables > .env file > YAML defaults.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LighthouseWorkspace(BaseSettings):
    """A single Sentinel workspace for Azure Lighthouse multi-tenant use."""

    workspace_id: str
    workspace_name: str
    resource_group: str
    subscription_id: str
    tenant_id: str = ""
    display_name: str = ""

    model_config = SettingsConfigDict(populate_by_name=True)


class AzureConfig(BaseSettings):
    tenant_id: str = Field("", alias="ATL_AZURE_TENANT_ID")
    client_id: str = Field("", alias="ATL_AZURE_CLIENT_ID")
    client_secret: SecretStr = Field(SecretStr(""), alias="ATL_AZURE_CLIENT_SECRET")
    subscription_id: str = Field("", alias="ATL_AZURE_SUBSCRIPTION_ID")
    auth_mode: str = Field("service_principal", alias="ATL_AZURE_AUTH_MODE")

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class SentinelConfig(BaseSettings):
    workspace_id: str = Field("", alias="ATL_SENTINEL_WORKSPACE_ID")
    workspace_name: str = Field("", alias="ATL_SENTINEL_WORKSPACE_NAME")
    resource_group: str = Field("", alias="ATL_SENTINEL_RESOURCE_GROUP")
    api_version: str = "2023-11-01"
    default_lookback_hours: int = 72
    max_incidents: int = 100
    # JSON-encoded list of LighthouseWorkspace dicts
    lighthouse_workspaces: list[LighthouseWorkspace] = Field(
        default_factory=list,
        alias="ATL_SENTINEL_WORKSPACES",
    )

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")

    def all_workspaces(self, subscription_id: str = "") -> list[LighthouseWorkspace]:
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
        for ws in self.all_workspaces(subscription_id):
            if ws.workspace_name == name_or_id or ws.workspace_id == name_or_id or ws.display_name == name_or_id:
                return ws
        return None


class DefenderConfig(BaseSettings):
    enabled: bool = Field(False, alias="ATL_DEFENDER_ENABLED")
    tenant_id: str = Field("", alias="ATL_DEFENDER_TENANT_ID")
    api_version: str = "2024-02-15"

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class LLMConfig(BaseSettings):
    """Azure OpenAI configuration (Entra ID auth – no API key required)."""

    endpoint: str = Field("", alias="ATL_LLM_ENDPOINT")
    deployment: str = Field("", alias="ATL_LLM_DEPLOYMENT")
    api_version: str = Field("", alias="ATL_LLM_API_VERSION")
    max_tokens: int = Field(4096, alias="ATL_LLM_MAX_TOKENS")
    temperature: float = 0.2
    fallback_provider: str = Field("", alias="ATL_LLM_FALLBACK_PROVIDER")
    openai_api_key: SecretStr = Field(SecretStr(""), alias="ATL_OPENAI_API_KEY")
    anthropic_api_key: SecretStr = Field(SecretStr(""), alias="ATL_ANTHROPIC_API_KEY")

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class BreachManagerFutureAPI(BaseSettings):
    name: str = ""
    enabled: bool = False
    endpoint_env_var: str = ""
    token_env_var: str = ""
    notes: str = ""

    model_config = SettingsConfigDict(populate_by_name=True)




class BreachManagerSkillConfig(BaseSettings):
    id: str = ""
    name: str = ""
    category: str = "custom"
    purpose: str = ""
    trigger_terms: list[str] = Field(default_factory=list)
    playbooks_supported: list[str] = Field(default_factory=list)

    model_config = SettingsConfigDict(populate_by_name=True)


class BreachManagerConfig(BaseSettings):
    default_auth_strategy: str = Field("service_principal", alias="ATL_BM_DEFAULT_AUTH_STRATEGY")
    default_tenant_ids: list[str] = Field(default_factory=list, alias="ATL_BM_TENANT_IDS")
    use_lighthouse: bool = Field(False, alias="ATL_BM_USE_LIGHTHOUSE")
    future_api_integrations: list[BreachManagerFutureAPI] = Field(
        default_factory=list,
        alias="ATL_BM_FUTURE_APIS",
    )
    local_skills: list[BreachManagerSkillConfig] = Field(
        default_factory=list,
        alias="ATL_BM_LOCAL_SKILLS",
    )

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class ThreatIntelConfig(BaseSettings):
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


class SecretSourceConfig(BaseSettings):
    source: str = Field("local", alias="ATL_SECRET_SOURCE")  # local | keyvault
    keyvault_uri: str = Field("", alias="ATL_KEYVAULT_URI")
    # JSON map of setting path -> Key Vault secret name
    # Example: {"azure.client_secret":"atl-azure-client-secret"}
    keyvault_secret_map: dict[str, str] = Field(default_factory=dict, alias="ATL_KEYVAULT_SECRET_MAP")

    model_config = SettingsConfigDict(populate_by_name=True, env_file=".env")


class Settings(BaseSettings):
    log_level: str = Field("INFO", alias="ATL_LOG_LEVEL")
    log_format: str = Field("console", alias="ATL_LOG_FORMAT")  # console | json
    output_format: str = Field("rich", alias="ATL_OUTPUT_FORMAT")  # rich | json | plain
    config_file: str = Field("config/default.yaml", alias="ATL_CONFIG_FILE")

    azure: AzureConfig = Field(default_factory=AzureConfig)
    sentinel: SentinelConfig = Field(default_factory=SentinelConfig)
    defender: DefenderConfig = Field(default_factory=DefenderConfig)
    secret_source: SecretSourceConfig = Field(default_factory=SecretSourceConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    breach_manager: BreachManagerConfig = Field(default_factory=BreachManagerConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    cache_ttl_seconds: int = Field(3600, alias="ATL_CACHE_TTL_SECONDS")

    _yaml_config: dict[str, Any] = {}

    model_config = SettingsConfigDict(
        populate_by_name=True,
        env_file=".env",
        env_nested_delimiter="__",
    )

    @model_validator(mode="after")
    def load_yaml_config(self) -> "Settings":
        config_path = Path(self.config_file)
        if config_path.exists():
            with config_path.open() as fh:
                self._yaml_config = yaml.safe_load(fh) or {}

        if self.secret_source.source.lower() == "keyvault" and self.secret_source.keyvault_uri:
            self._load_secrets_from_keyvault()
        return self

    def _load_secrets_from_keyvault(self) -> None:
        secret_map = {
            "azure.client_secret": "ATL_AZURE_CLIENT_SECRET",
            "llm.openai_api_key": "ATL_OPENAI_API_KEY",
            "llm.anthropic_api_key": "ATL_ANTHROPIC_API_KEY",
            "threat_intel.virustotal_api_key": "ATL_VIRUSTOTAL_API_KEY",
            "threat_intel.greynoise_api_key": "ATL_GREYNOISE_API_KEY",
            "threat_intel.abuseipdb_api_key": "ATL_ABUSEIPDB_API_KEY",
        }
        secret_map.update(self.secret_source.keyvault_secret_map)

        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except Exception as exc:  # pragma: no cover - import error path is environment-dependent
            raise RuntimeError(
                "Key Vault secret source is configured but azure-keyvault-secrets is not available"
            ) from exc

        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=self.secret_source.keyvault_uri, credential=credential)

        for field_path, secret_name in secret_map.items():
            if self._field_has_value(field_path):
                continue
            try:
                secret_value = client.get_secret(secret_name).value
            except Exception:
                continue
            if secret_value:
                self._set_secret_field(field_path, secret_value)

    def _field_has_value(self, field_path: str) -> bool:
        node: Any = self
        parts = field_path.split(".")
        for part in parts[:-1]:
            node = getattr(node, part)
        value = getattr(node, parts[-1])
        if isinstance(value, SecretStr):
            return bool(value.get_secret_value())
        return bool(value)

    def _set_secret_field(self, field_path: str, value: str) -> None:
        node: Any = self
        parts = field_path.split(".")
        for part in parts[:-1]:
            node = getattr(node, part)
        current = getattr(node, parts[-1])
        if isinstance(current, SecretStr):
            setattr(node, parts[-1], SecretStr(value))
        else:
            setattr(node, parts[-1], value)

    def get_yaml(self, *keys: str, default: Any = None) -> Any:
        """Navigate nested YAML: get_yaml('sentinel', 'max_incidents')."""
        node: Any = self._yaml_config
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key, default)
        return node

    @property
    def is_llm_configured(self) -> bool:
        return bool(self.llm.endpoint and self.llm.deployment)

    @property
    def is_azure_configured(self) -> bool:
        return bool(self.azure.tenant_id and self.azure.client_id)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()
