"""Unit tests for the settings module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from azure_threat_lens.config.settings import AppSettings, reload_settings


class TestAppSettings:
    def test_defaults(self) -> None:
        settings = AppSettings()
        assert settings.log_level == "INFO"
        assert settings.log_format == "console"
        assert settings.output_format == "rich"

    def test_env_override(self) -> None:
        with patch.dict(os.environ, {"ATL_LOG_LEVEL": "DEBUG", "ATL_OUTPUT_FORMAT": "json"}):
            settings = AppSettings()
            assert settings.log_level == "DEBUG"
            assert settings.output_format == "json"

    def test_is_azure_configured_false(self) -> None:
        settings = AppSettings()
        # Without env vars set, Azure should not be configured
        if not os.environ.get("ATL_AZURE_TENANT_ID"):
            assert settings.is_azure_configured is False

    def test_is_llm_configured_false(self) -> None:
        with patch.dict(os.environ, {"ATL_ANTHROPIC_API_KEY": ""}):
            settings = AppSettings()
            assert settings.is_llm_configured is False

    def test_is_llm_configured_true(self) -> None:
        with patch.dict(os.environ, {"ATL_ANTHROPIC_API_KEY": "sk-ant-test-key"}):
            settings = AppSettings()
            assert settings.is_llm_configured is True

    def test_threat_intel_enabled_flags(self) -> None:
        with patch.dict(os.environ, {"ATL_VIRUSTOTAL_API_KEY": "vt-key", "ATL_GREYNOISE_API_KEY": ""}):
            settings = AppSettings()
            assert settings.threat_intel.virustotal_enabled is True
            assert settings.threat_intel.greynoise_enabled is False

    def test_get_yaml_default(self) -> None:
        settings = AppSettings()
        # Should return default when key doesn't exist
        result = settings.get_yaml("nonexistent", "key", default="fallback")
        assert result == "fallback"
