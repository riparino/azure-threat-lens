from __future__ import annotations

from threatlens.models.investigations import InvestigationFinding


class ResourceAccessAnalyzer:
    def analyze(self, resource_context: dict[str, str]) -> list[InvestigationFinding]:
        return [
            InvestigationFinding(
                title="Resource context resolved",
                severity="informational",
                details="Resource context collected via Azure Resource Graph.",
                evidence=resource_context,
            )
        ]
