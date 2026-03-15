"""Breach Manager planning engine.

Deterministic triage/remediation planner for enterprise Azure estates.
The engine is explicitly proposal-only: it never executes commands.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.core.breach_skill_registry import BreachSkillRegistry
from threatlens.models.breach_manager import (
    BreachAction,
    BreachManagerPlan,
    CommandProposal,
    FutureAPIIntegration,
    GuidanceLink,
    RemediationTool,
    TenantTarget,
)
from threatlens.utils.config import get_settings


@dataclass(slots=True)
class BreachManagerInput:
    scenario: str
    mode: str = "reactive"
    auth_strategy: str = "service_principal"
    tenant_ids: list[str] | None = None
    incident: dict | None = None
    lighthouse: bool = False


class BreachManagerEngine:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.registry = BreachSkillRegistry(self.settings.breach_manager.local_skills)

    async def plan(self, data: BreachManagerInput) -> BreachManagerPlan:
        context = self._context_text(data)
        matched = self.registry.match(context)
        tools = self._tools_catalog(matched.selected_playbooks)

        return BreachManagerPlan(
            operation_name="Azure Breach Manager",
            input_mode=data.mode,
            auth_strategy=data.auth_strategy,
            execution_policy="proposal_only",
            selected_playbooks=matched.selected_playbooks,
            attack_path_hypotheses=self._hypotheses(matched.selected_playbooks, data),
            triage_checkpoints=self._triage_checkpoints(matched.selected_playbooks, data),
            tenant_targets=self._tenant_targets(data),
            skills=matched.selected_skills,
            tools=tools,
            actions=self._build_actions(matched.selected_playbooks),
            future_api_integrations=self._future_integrations(),
            skill_registry_mode="in_app",
        )

    def _context_text(self, data: BreachManagerInput) -> str:
        incident = data.incident or {}
        parts = [
            data.scenario.lower(),
            str(incident.get("title", "")).lower(),
            str(incident.get("description", "")).lower(),
            str(incident.get("severity", "")).lower(),
        ]
        return " ".join(parts)

    def _tools_catalog(self, playbooks: list[str]) -> list[RemediationTool]:
        tools = [
            RemediationTool(
                id="tool.sentinel.timeline",
                name="Sentinel Timeline Investigator",
                purpose="Correlate incidents, alerts, entities, and KQL pivots.",
            ),
            RemediationTool(
                id="tool.identity.session_revoke",
                name="Identity Session Revocation Planner",
                purpose="Generate token/session revocation proposals for users/SPs.",
            ),
            RemediationTool(
                id="tool.change_executor",
                name="Human-Confirmed Change Executor",
                purpose="Only executes actions after explicit analyst approval.",
            ),
        ]
        if "AKS App-to-Identity Pivot" in playbooks:
            tools.append(
                RemediationTool(
                    id="tool.aks.audit",
                    name="AKS Audit Pivot Tool",
                    purpose="Trace namespace, service account, and secret access chains.",
                )
            )
        return tools

    def _hypotheses(self, playbooks: list[str], data: BreachManagerInput) -> list[str]:
        base = [
            "Adversary established persistence before first visible Sentinel incident.",
            "Identity and token abuse are likely enabling cross-subscription movement.",
        ]
        if "O365 Phishing to Entra Takeover" in playbooks:
            base.append("Phishing-generated session hijack may have bypassed MFA through token theft.")
        if "Endpoint Malware to Cloud Pivot" in playbooks:
            base.append("Endpoint compromise likely enabled credential theft and cloud control-plane pivoting.")
        if "Ransomware Impact Containment" in playbooks:
            base.append("Adversary likely performed discovery and backup tampering before encryption stage.")
        if "AKS App-to-Identity Pivot" in playbooks:
            base.append("Compromised workload exposed secrets/tokens used to control Azure APIs.")
        if "Identity Privilege Escalation" in playbooks:
            base.append("Rogue service principal/app consent may maintain privileged persistence.")
        if "Storage/KeyVault Data Exfiltration" in playbooks:
            base.append("Data access keys or SAS tokens may still be valid for ongoing exfiltration.")
        if (data.incident or {}).get("severity", "").lower() in {"high", "critical"}:
            base.append("Treat as active enterprise breach; prioritize containment over deep forensic wait.")
        return base

    def _triage_checkpoints(self, playbooks: list[str], data: BreachManagerInput) -> list[str]:
        checks = [
            "Confirm blast radius by tenant, subscription, workspace, and critical business services.",
            "Classify entities as confirmed-compromised vs related-context before containment.",
            "Require explicit analyst confirmation before any disabling/deletion/rotation action.",
        ]
        if data.lighthouse:
            checks.append("Validate Lighthouse delegation scope and break-glass access path.")
        if "O365 Phishing to Entra Takeover" in playbooks:
            checks.append("Check mailbox rules, OAuth consent grants, and impossible travel sign-ins.")
        if "Endpoint Malware to Cloud Pivot" in playbooks:
            checks.append("Validate MDE device isolation status and credential dumping indicators.")
        if "Ransomware Impact Containment" in playbooks:
            checks.append("Check for backup deletion, mass encryption patterns, and staged exfil events.")
        if "AKS App-to-Identity Pivot" in playbooks:
            checks.append("Trace secret access and workload identity token usage by namespace.")
        return checks

    def _tenant_targets(self, data: BreachManagerInput) -> list[TenantTarget]:
        tenant_ids = data.tenant_ids or self.settings.breach_manager.default_tenant_ids
        if not tenant_ids:
            tenant_ids = [self.settings.azure.tenant_id] if self.settings.azure.tenant_id else []
        lighthouse_mode = data.lighthouse or self.settings.breach_manager.use_lighthouse
        return [
            TenantTarget(
                tenant_id=t,
                subscription_id=self.settings.azure.subscription_id,
                workspace_name=self.settings.sentinel.workspace_name,
                lighthouse_delegated=lighthouse_mode,
            )
            for t in tenant_ids
        ]

    def _build_actions(self, playbooks: list[str]) -> list[BreachAction]:
        nist = GuidanceLink(
            framework="NIST SP 800-61r2",
            title="Computer Security Incident Handling Guide",
            url="https://csrc.nist.gov/pubs/sp/800/61/r2/final",
        )
        cisa = GuidanceLink(
            framework="CISA",
            title="Cyber Incident Response Guide",
            url="https://www.cisa.gov/resources-tools/resources/cisa-cyber-incident-response-guide",
        )
        msrc = GuidanceLink(
            framework="Microsoft",
            title="Microsoft Security Incident Response Guidance",
            url="https://learn.microsoft.com/security/operations/incident-response-playbooks",
        )
        dfi = GuidanceLink(
            framework="Microsoft",
            title="Defender for Identity Incident Response",
            url="https://learn.microsoft.com/defender-for-identity/respond-to-suspicious-activities",
        )

        actions = [
            BreachAction(
                phase="discover",
                objective="Build unified timeline across Sentinel, Entra, endpoint, and cloud control-plane logs",
                details="Correlate first malicious event, privilege changes, and pivot sequence.",
                guidance=[nist, msrc],
                skill_ids=["skill.identity.isolation"],
                tool_ids=["tool.sentinel.timeline"],
                command_proposals=[],
            ),
            BreachAction(
                phase="contain",
                objective="Contain compromised identities and workloads",
                details="Prepare revocation/isolation actions but execute only after analyst confirmation.",
                guidance=[nist, cisa, dfi],
                skill_ids=["skill.identity.isolation"],
                tool_ids=["tool.identity.session_revoke", "tool.change_executor"],
                command_proposals=[
                    CommandProposal(
                        title="Disable compromised user",
                        command="az ad user update --id <user-upn-or-id> --account-enabled false",
                        reason="Stop active abuse from confirmed-compromised identity.",
                        risk="high",
                    ),
                    CommandProposal(
                        title="Revoke Entra refresh tokens",
                        command="az rest --method POST --url https://graph.microsoft.com/v1.0/users/<id>/revokeSignInSessions",
                        reason="Invalidate stolen tokens.",
                    ),
                ],
            ),
            BreachAction(
                phase="evict",
                objective="Remove persistence and abusive privileges",
                details="Remove rogue app creds/consents/role assignments and known persistence mechanisms.",
                guidance=[cisa, msrc],
                skill_ids=["skill.identity.isolation"],
                tool_ids=["tool.change_executor"],
                command_proposals=[
                    CommandProposal(
                        title="Remove suspect role assignment",
                        command="az role assignment delete --assignee <principal-id> --role <role> --scope <scope>",
                        reason="Evict illicit privilege persistence.",
                        risk="high",
                    )
                ],
            ),
            BreachAction(
                phase="recover",
                objective="Recover workloads and business services",
                details="Restore from known-good baselines, rotate secrets, and monitor re-entry indicators.",
                guidance=[nist, cisa],
                skill_ids=["skill.data.exfil"],
                tool_ids=["tool.change_executor"],
                command_proposals=[],
            ),
            BreachAction(
                phase="harden",
                objective="Harden posture with repeatable controls and simulations",
                details="Enforce PIM/JIT, CA hardening, workload identity controls, and purple-team validation.",
                guidance=[msrc],
                skill_ids=["skill.identity.isolation"],
                tool_ids=[],
                command_proposals=[],
            ),
        ]

        if "AKS App-to-Identity Pivot" in playbooks:
            actions.append(
                BreachAction(
                    phase="contain",
                    objective="Suspend suspicious AKS workloads and revoke exposed workload identities",
                    details="Quarantine namespaces and block token replay paths from compromised pods.",
                    guidance=[cisa, msrc],
                    skill_ids=["skill.aks.forensics"],
                    tool_ids=["tool.aks.audit", "tool.change_executor"],
                    command_proposals=[
                        CommandProposal(
                            title="Disable local AKS accounts",
                            command="az aks update -g <rg> -n <cluster> --disable-local-accounts true",
                            reason="Reduce attacker fallback auth paths.",
                            risk="medium",
                        )
                    ],
                )
            )

        if "Endpoint Malware to Cloud Pivot" in playbooks or "Ransomware Impact Containment" in playbooks:
            actions.append(
                BreachAction(
                    phase="contain",
                    objective="Coordinate endpoint isolation with cloud containment",
                    details="Request MDE isolation and block compromised host identities from cloud operations.",
                    guidance=[cisa, msrc],
                    skill_ids=["skill.endpoint.containment"],
                    tool_ids=["tool.change_executor"],
                    command_proposals=[
                        CommandProposal(
                            title="Block VM run command",
                            command="az role assignment create --assignee <ir-sp> --role Reader --scope <vm-scope>",
                            reason="Restrict risky remote admin during active containment.",
                            risk="medium",
                        )
                    ],
                )
            )

        return actions

    def _future_integrations(self) -> list[FutureAPIIntegration]:
        defaults = [
            FutureAPIIntegration(
                name="Attack Path Graph API",
                endpoint_env_var="ATL_BM_ATTACK_PATH_API_URL",
                token_env_var="ATL_BM_ATTACK_PATH_API_TOKEN",
                notes="Planned API for graphing attacker movement and privilege chains.",
            ),
            FutureAPIIntegration(
                name="Automated Containment Orchestrator API",
                endpoint_env_var="ATL_BM_ORCHESTRATOR_API_URL",
                token_env_var="ATL_BM_ORCHESTRATOR_API_TOKEN",
                notes="Planned API for controlled execution after analyst approval.",
            ),
        ]
        configured = self.settings.breach_manager.future_api_integrations
        return configured if configured else defaults
