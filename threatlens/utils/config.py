from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATLENS_", env_file=".env", extra="ignore")

    azure_tenant_id: str = Field(default="")
    azure_client_id: str = Field(default="")
    azure_client_secret: str = Field(default="")
    default_subscription_id: str = Field(default="")
    sentinel_workspace_id: str = Field(default="")

    virustotal_api_key: str = Field(default="")
    greynoise_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")


settings = Settings()
