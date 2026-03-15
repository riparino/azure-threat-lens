from __future__ import annotations


def analyze_identity_abuse(profile: dict[str, object]) -> list[str]:
    findings: list[str] = []
    if not profile.get("mfa_enabled", True):
        findings.append("Identity does not have MFA enabled")
    if int(profile.get("recent_failed_signins", 0)) > 5:
        findings.append("High failed sign-in count observed")
    if profile.get("risk_level") == "high":
        findings.append("Identity has elevated risk in Entra ID")
    return findings
