from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from threatlens.models.entities import Entity


class Alert(BaseModel):
    alert_id: str
    title: str
    severity: str
    description: str = ""


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    alerts: list[Alert] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
