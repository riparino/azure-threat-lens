from __future__ import annotations

from threatlens.models.investigations import InvestigationFinding


class PrivilegeEscalationAnalyzer:
    def analyze(self, events: list[dict[str, str]]) -> list[InvestigationFinding]:
        for event in events:
            if "roleassignments/write" in event.get("operationName", "").lower():
                return [
                    InvestigationFinding(
                        title="Role assignment change",
                        severity="high",
                        details="Observed role assignment write action.",
                        evidence=event,
                    )
                ]
        return []
