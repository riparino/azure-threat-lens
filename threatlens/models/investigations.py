from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class InvestigationFinding(BaseModel):
    title: str
    severity: str
    details: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class InvestigationReport(BaseModel):
    report_type: str
    target: str
    summary: str
    risk_score: int = 0
    findings: list[InvestigationFinding] = Field(default_factory=list)
    guidance: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
