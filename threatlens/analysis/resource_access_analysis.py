from __future__ import annotations


def analyze_resource_access(resource: dict[str, object]) -> list[str]:
    findings: list[str] = []
    tags = resource.get("tags", {})
    if isinstance(tags, dict) and tags.get("environment") == "prod":
        findings.append("Resource is production scoped and requires heightened review")
    if resource.get("related"):
        findings.append("Related resources detected, expand blast-radius assessment")
    return findings
