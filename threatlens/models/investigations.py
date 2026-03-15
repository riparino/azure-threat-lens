from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class InvestigationFinding(BaseModel):
    category: str
    summary: str
    severity: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class InvestigationReport(BaseModel):
    report_id: str
    investigation_type: str
    target: str
    risk_score: int
    verdict: str
    summary: str
    findings: list[InvestigationFinding] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
