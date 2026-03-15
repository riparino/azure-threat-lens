from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Entity(BaseModel):
    entity_type: str
    name: str
    value: str
    properties: dict[str, Any] = Field(default_factory=dict)


class ResolvedEntity(BaseModel):
    entity: Entity
    context: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.5
