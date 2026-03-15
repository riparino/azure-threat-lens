from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    account = "account"
    ip = "ip"
    host = "host"
    azure_resource = "azure_resource"
    url = "url"
    file_hash = "file_hash"
    unknown = "unknown"


class Entity(BaseModel):
    entity_id: str
    entity_type: EntityType
    value: str
    properties: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.5


class EntityResolutionResult(BaseModel):
    entity: Entity
    resolved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    related_entities: list[Entity] = Field(default_factory=list)
    observables: dict[str, Any] = Field(default_factory=dict)
