"""Configuration module."""

from azure_threat_lens.config.settings import AppSettings, get_settings, reload_settings

__all__ = ["AppSettings", "get_settings", "reload_settings"]
