from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from threatlens.models.entities import Entity


class Alert(BaseModel):
    alert_id: str
    title: str
    severity: str
    description: str = ""
    entities: list[Entity] = Field(default_factory=list)


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str = "active"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    alerts: list[Alert] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
