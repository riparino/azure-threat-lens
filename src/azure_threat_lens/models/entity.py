"""Pydantic models for Azure entities (IPs, hosts, accounts, URLs, files)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityKind(str, Enum):
    IP = "Ip"
    HOST = "Host"
    ACCOUNT = "Account"
    URL = "Url"
    FILE = "File"
    FILE_HASH = "FileHash"
    PROCESS = "Process"
    CLOUD_APPLICATION = "CloudApplication"
    DNS = "DnsResolution"
    REGISTRY_KEY = "RegistryKey"
    REGISTRY_VALUE = "RegistryValue"
    SECURITY_GROUP = "SecurityGroup"
    AZURE_RESOURCE = "AzureResource"
    MAILBOX = "Mailbox"
    MAIL_MESSAGE = "MailMessage"
    SUBMISSION_MAIL = "SubmissionMail"
    UNKNOWN = "Unknown"


class ThreatIntelHit(BaseModel):
    """A single threat intelligence match from any provider."""

    provider: str
    malicious: bool = False
    suspicious: bool = False
    score: float | None = None
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IPEntityContext(BaseModel):
    """Contextual data for an IP address entity."""

    address: str
    asn: int | None = None
    asn_org: str = ""
    country: str = ""
    city: str = ""
    is_private: bool = False
    is_tor: bool = False
    is_vpn: bool = False
    is_cloud: bool = False
    cloud_provider: str = ""
    threat_intel: list[ThreatIntelHit] = Field(default_factory=list)
    related_incidents: list[str] = Field(default_factory=list)
    azure_network_resources: list[dict[str, Any]] = Field(default_factory=list)


class HostEntityContext(BaseModel):
    """Contextual data for a host/machine entity."""

    hostname: str
    fqdn: str = ""
    os_name: str = ""
    os_version: str = ""
    azure_resource_id: str = ""
    subscription_id: str = ""
    resource_group: str = ""
    is_azure_vm: bool = False
    is_domain_joined: bool = False
    defender_risk_score: str = ""
    recent_alerts: list[dict[str, Any]] = Field(default_factory=list)
    installed_software: list[str] = Field(default_factory=list)


class EntityResolutionResult(BaseModel):
    """Output of entity context resolution."""

    entity_kind: EntityKind
    identifier: str
    display_name: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    threat_intel_hits: list[ThreatIntelHit] = Field(default_factory=list)
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    risk_label: str = "Unknown"
    related_incidents: list[str] = Field(default_factory=list)
    azure_resource_details: dict[str, Any] = Field(default_factory=dict)
    llm_analysis: str = ""
    resolved_at: datetime = Field(default_factory=datetime.utcnow)
    raw_data: dict[str, Any] = Field(default_factory=dict)
