"""Unit tests for the settings module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from threatlens.utils.config import Settings, reload_settings


class TestSettings:
    def test_defaults(self) -> None:
        settings = Settings()
        assert settings.log_level == "INFO"
        assert settings.log_format == "console"
        assert settings.output_format == "rich"

    def test_env_override(self) -> None:
        with patch.dict(os.environ, {"ATL_LOG_LEVEL": "DEBUG", "ATL_OUTPUT_FORMAT": "json"}):
            settings = Settings()
            assert settings.log_level == "DEBUG"
            assert settings.output_format == "json"

    def test_is_azure_configured_false(self) -> None:
        settings = Settings()
        if not os.environ.get("ATL_AZURE_TENANT_ID"):
            assert settings.is_azure_configured is False

    def test_is_llm_configured_false(self) -> None:
        with patch.dict(os.environ, {"ATL_LLM_ENDPOINT": "", "ATL_LLM_DEPLOYMENT": ""}):
            settings = Settings()
            assert settings.is_llm_configured is False

    def test_is_llm_configured_true(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ATL_LLM_ENDPOINT": "https://my-resource.openai.azure.com/",
                "ATL_LLM_DEPLOYMENT": "gpt-4o",
            },
        ):
            settings = Settings()
            assert settings.is_llm_configured is True

    def test_threat_intel_enabled_flags(self) -> None:
        with patch.dict(os.environ, {"ATL_VIRUSTOTAL_API_KEY": "vt-key", "ATL_GREYNOISE_API_KEY": ""}):
            settings = Settings()
            assert settings.threat_intel.virustotal_enabled is True
            assert settings.threat_intel.greynoise_enabled is False

    def test_get_yaml_default(self) -> None:
        settings = Settings()
        result = settings.get_yaml("nonexistent", "key", default="fallback")
        assert result == "fallback"

    def test_cache_ttl_default(self) -> None:
        settings = Settings()
        assert settings.cache_ttl_seconds == 3600

    def test_llm_config_fields(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ATL_LLM_ENDPOINT": "https://test.openai.azure.com/",
                "ATL_LLM_DEPLOYMENT": "gpt-4o",
                "ATL_LLM_API_VERSION": "2024-02-01",
            },
        ):
            settings = Settings()
            assert settings.llm.endpoint == "https://test.openai.azure.com/"
            assert settings.llm.deployment == "gpt-4o"
            assert settings.llm.api_version == "2024-02-01"
