from __future__ import annotations

from pydantic import BaseModel


class Settings(BaseModel):
    environment: str = "dev"
    tenant_id: str = ""
