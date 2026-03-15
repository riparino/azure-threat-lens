"""In-application Breach Manager skill registry.

Skills are maintained inside this application and can be expanded via configuration,
without requiring an external skills service.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.models.breach_manager import RemediationSkill
from threatlens.utils.config import BreachManagerSkillConfig


@dataclass(slots=True)
class SkillMatch:
    selected_skills: list[RemediationSkill]
    selected_playbooks: list[str]


class BreachSkillRegistry:
    """Registry for built-in and locally configured remediation skills."""

    def __init__(self, local_skills: list[BreachManagerSkillConfig] | None = None) -> None:
        self._skills = self._default_skills()
        for local in local_skills or []:
            self._skills.append(
                RemediationSkill(
                    id=local.id,
                    name=local.name,
                    category=local.category,
                    purpose=local.purpose,
                    trigger_terms=local.trigger_terms,
                    playbooks_supported=local.playbooks_supported,
                )
            )

    def match(self, text: str) -> SkillMatch:
        selected = [
            skill for skill in self._skills if any(term in text for term in skill.trigger_terms)
        ]
        if not selected:
            selected = [
                RemediationSkill(
                    id="skill.generic.enterprise",
                    name="Generic Enterprise Containment Skill",
                    category="general",
                    purpose="Baseline containment and analyst-guided remediation when scenario-specific skills do not match.",
                    trigger_terms=[],
                    playbooks_supported=["Generic Enterprise Containment"],
                )
            ]
        playbooks: list[str] = []
        for skill in selected:
            for pb in skill.playbooks_supported:
                if pb not in playbooks:
                    playbooks.append(pb)
        return SkillMatch(selected_skills=selected, selected_playbooks=playbooks)

    def _default_skills(self) -> list[RemediationSkill]:
        return [
            RemediationSkill(
                id="skill.identity.isolation",
                name="Identity Isolation Skill",
                category="identity",
                purpose="Disable/restrict compromised users, apps, and tokens with human approval.",
                trigger_terms=["phish", "m365", "o365", "mailbox", "inbox rule", "aad", "token", "service principal", "global admin", "consent", "role assignment"],
                playbooks_supported=["O365 Phishing to Entra Takeover", "Identity Privilege Escalation"],
            ),
            RemediationSkill(
                id="skill.endpoint.containment",
                name="Endpoint Containment Skill",
                category="endpoint",
                purpose="Coordinate MDE isolation and malware triage before cloud-side cleanup.",
                trigger_terms=["defender for endpoint", "malware", "beacon", "c2", "lateral", "ransom", "encryption", "extortion"],
                playbooks_supported=["Endpoint Malware to Cloud Pivot", "Ransomware Impact Containment"],
            ),
            RemediationSkill(
                id="skill.aks.forensics",
                name="Kubernetes Forensics Skill",
                category="kubernetes",
                purpose="Collect pod/audit evidence and map secret/workload identity abuse.",
                trigger_terms=["aks", "kubernetes", "pod", "secret", "workload identity"],
                playbooks_supported=["AKS App-to-Identity Pivot"],
            ),
            RemediationSkill(
                id="skill.vm.lateral",
                name="VM Lateral Movement Skill",
                category="compute",
                purpose="Investigate VM pivoting and contain host-driven lateral movement.",
                trigger_terms=["vm", "rdp", "ssh", "run command", "pivot"],
                playbooks_supported=["VM Lateral Movement"],
            ),
            RemediationSkill(
                id="skill.data.exfil",
                name="Data Exfiltration Response Skill",
                category="data",
                purpose="Contain storage/key vault abuse and rotate exposed credentials.",
                trigger_terms=["key vault", "listkeys", "sas", "blob", "exfil"],
                playbooks_supported=["Storage/KeyVault Data Exfiltration"],
            ),
        ]
