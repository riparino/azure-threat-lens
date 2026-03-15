"""Models for the Breach Manager workflow."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GuidanceLink(BaseModel):
    framework: str
    title: str
    url: str


class FutureAPIIntegration(BaseModel):
    name: str
    enabled: bool = False
    endpoint_env_var: str = ""
    token_env_var: str = ""
    notes: str = ""


class RemediationSkill(BaseModel):
    id: str
    name: str
    category: str
    purpose: str
    trigger_terms: list[str] = Field(default_factory=list)
    playbooks_supported: list[str] = Field(default_factory=list)


class RemediationTool(BaseModel):
    id: str
    name: str
    purpose: str
    requires_human_approval: bool = True


class CommandProposal(BaseModel):
    title: str
    command: str
    reason: str
    risk: str = "medium"
    auto_executable: bool = False


class BreachAction(BaseModel):
    phase: str
    objective: str
    details: str
    requires_approval: bool = True
    guidance: list[GuidanceLink] = Field(default_factory=list)
    skill_ids: list[str] = Field(default_factory=list)
    tool_ids: list[str] = Field(default_factory=list)
    command_proposals: list[CommandProposal] = Field(default_factory=list)


class TenantTarget(BaseModel):
    tenant_id: str
    subscription_id: str = ""
    workspace_name: str = ""
    lighthouse_delegated: bool = False


class BreachManagerPlan(BaseModel):
    operation_name: str
    input_mode: str
    auth_strategy: str
    execution_policy: str = "proposal_only"
    selected_playbooks: list[str] = Field(default_factory=list)
    attack_path_hypotheses: list[str] = Field(default_factory=list)
    triage_checkpoints: list[str] = Field(default_factory=list)
    tenant_targets: list[TenantTarget] = Field(default_factory=list)
    skills: list[RemediationSkill] = Field(default_factory=list)
    tools: list[RemediationTool] = Field(default_factory=list)
    actions: list[BreachAction] = Field(default_factory=list)
    future_api_integrations: list[FutureAPIIntegration] = Field(default_factory=list)
    skill_registry_mode: str = "in_app"
