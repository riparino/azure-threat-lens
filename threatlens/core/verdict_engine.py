from __future__ import annotations

from threatlens.models.investigations import InvestigationFinding


class VerdictEngine:
    def score(self, findings: list[InvestigationFinding]) -> int:
        weights = {"critical": 95, "high": 75, "medium": 50, "low": 25, "informational": 10}
        if not findings:
            return 0
        return int(sum(weights.get(f.severity, 0) for f in findings) / len(findings))
