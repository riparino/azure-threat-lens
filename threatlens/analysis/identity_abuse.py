from __future__ import annotations

from threatlens.models.investigations import InvestigationFinding


class IdentityAbuseAnalyzer:
    def analyze(self, identity_context: dict[str, object]) -> list[InvestigationFinding]:
        findings: list[InvestigationFinding] = []
        if not identity_context.get("mfaRegistered", False):
            findings.append(
                InvestigationFinding(
                    title="MFA not registered",
                    severity="high",
                    details="Identity has no MFA registration.",
                    evidence={"identity": identity_context.get("identity")},
                )
            )
        risk_level = str(identity_context.get("riskLevel", "low")).lower()
        if risk_level in {"high", "medium"}:
            findings.append(
                InvestigationFinding(
                    title="Identity risk signal",
                    severity=risk_level,
                    details="Graph reported elevated identity risk.",
                    evidence=identity_context,
                )
            )
        return findings
