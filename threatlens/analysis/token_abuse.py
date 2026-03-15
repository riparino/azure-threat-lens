from __future__ import annotations

from threatlens.models.investigations import InvestigationFinding


class TokenAbuseAnalyzer:
    def analyze(self, events: list[dict[str, str]]) -> list[InvestigationFinding]:
        suspicious = [event for event in events if "token" in event.get("operationName", "").lower()]
        if not suspicious:
            return []
        return [
            InvestigationFinding(
                title="Potential token abuse",
                severity="medium",
                details="Detected token-related operations requiring review.",
                evidence={"events": suspicious},
            )
        ]
