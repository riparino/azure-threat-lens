"""Incident and alert data models for Microsoft Sentinel."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from threatlens.models.entities import RawEntity


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class IncidentStatus(str, Enum):
    NEW = "New"
    ACTIVE = "Active"
    CLOSED = "Closed"


class Classification(str, Enum):
    TRUE_POSITIVE = "TruePositive"
    FALSE_POSITIVE = "FalsePositive"
    BENIGN_POSITIVE = "BenignPositive"
    UNDETERMINED = "Undetermined"


class Alert(BaseModel):
    """A single Sentinel alert linked to an incident."""

    alert_id: str = Field(..., alias="systemAlertId")
    display_name: str = Field("", alias="alertDisplayName")
    severity: Severity = Field(Severity.INFORMATIONAL)
    description: str = ""
    provider_name: str = Field("", alias="providerName")
    product_name: str = Field("", alias="productName")
    status: str = ""
    time_generated: datetime | None = Field(None, alias="timeGenerated")
    entities: list[RawEntity] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    extended_properties: dict[str, Any] = Field(default_factory=dict, alias="extendedProperties")

    model_config = {"populate_by_name": True}


class IncidentLabel(BaseModel):
    label_name: str = Field(..., alias="labelName")
    label_type: str = Field("", alias="labelType")

    model_config = {"populate_by_name": True}


class Incident(BaseModel):
    """A Microsoft Sentinel incident."""

    incident_id: str = Field(..., alias="incidentId")
    incident_number: int = Field(0, alias="incidentNumber")
    title: str = ""
    description: str = ""
    severity: Severity = Field(Severity.INFORMATIONAL)
    status: IncidentStatus = Field(IncidentStatus.NEW)
    classification: Classification | None = None
    owner: dict[str, Any] = Field(default_factory=dict)
    labels: list[IncidentLabel] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    entities: list[RawEntity] = Field(default_factory=list)
    created_time_utc: datetime | None = Field(None, alias="createdTimeUtc")
    last_modified_time_utc: datetime | None = Field(None, alias="lastModifiedTimeUtc")
    first_activity_time_utc: datetime | None = Field(None, alias="firstActivityTimeUtc")
    last_activity_time_utc: datetime | None = Field(None, alias="lastActivityTimeUtc")
    alert_ids: list[str] = Field(default_factory=list, alias="relatedAlertIds")
    provider_incident_id: str = Field("", alias="providerIncidentId")

    model_config = {"populate_by_name": True}
