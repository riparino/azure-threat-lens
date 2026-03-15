from __future__ import annotations


def analyze_privilege_escalation(activity: list[dict[str, str]]) -> list[str]:
    findings: list[str] = []
    for event in activity:
        if "roleAssignments/write" in event.get("operation", ""):
            findings.append("Role assignment changes detected")
    return findings
