"""Entity data models.

Covers all Azure/security entity types that can appear in Sentinel incidents:
IP addresses, hostnames, accounts, URLs, file hashes, Azure resources, etc.
"""

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
    """A threat intelligence result from a single provider."""

    provider: str
    malicious: bool = False
    suspicious: bool = False
    score: float | None = None
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ResolvedEntity(BaseModel):
    """A fully resolved entity with contextual and threat intelligence data."""

    entity_kind: EntityKind
    identifier: str
    display_name: str = ""

    # Enrichment
    context: dict[str, Any] = Field(default_factory=dict)
    threat_intel_hits: list[ThreatIntelHit] = Field(default_factory=list)
    azure_resource_details: dict[str, Any] = Field(default_factory=dict)

    # Risk
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    risk_label: str = "Unknown"
    risk_indicators: list[str] = Field(default_factory=list)

    # Cross-references
    related_incidents: list[str] = Field(default_factory=list)

    # Analysis
    llm_analysis: str = ""
    resolved_at: datetime = Field(default_factory=datetime.utcnow)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class RawEntity(BaseModel):
    """An entity as it arrives from a Sentinel alert or incident (pre-resolution)."""

    entity_type: str = Field(..., alias="entityType")
    friendly_name: str = Field("", alias="friendlyName")
    properties: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    def primary_identifier(self) -> str:
        """Return the most meaningful identifier for this entity."""
        props = self.properties
        return (
            props.get("address")
            or props.get("userPrincipalName")
            or props.get("accountName")
            or props.get("hostName")
            or props.get("url")
            or props.get("hashValue")
            or self.friendly_name
            or ""
        )
