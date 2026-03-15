"""Pydantic models for identity and Entra ID / AAD investigation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SignInRiskLevel(str):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    HIDDEN = "hidden"
    UNKNOWN_FUTURE_VALUE = "unknownFutureValue"


class SignInEvent(BaseModel):
    """A single Entra ID sign-in log entry."""

    id: str = ""
    user_display_name: str = Field("", alias="userDisplayName")
    user_principal_name: str = Field("", alias="userPrincipalName")
    user_id: str = Field("", alias="userId")
    app_display_name: str = Field("", alias="appDisplayName")
    app_id: str = Field("", alias="appId")
    ip_address: str = Field("", alias="ipAddress")
    client_app_used: str = Field("", alias="clientAppUsed")
    conditional_access_status: str = Field("", alias="conditionalAccessStatus")
    is_interactive: bool = Field(True, alias="isInteractive")
    risk_level_during_signin: str = Field("none", alias="riskLevelDuringSignIn")
    risk_state: str = Field("none", alias="riskState")
    status: dict[str, Any] = Field(default_factory=dict)
    location: dict[str, Any] = Field(default_factory=dict)
    device_detail: dict[str, Any] = Field(default_factory=dict, alias="deviceDetail")
    created_date_time: datetime | None = Field(None, alias="createdDateTime")
    mfa_detail: dict[str, Any] = Field(default_factory=dict, alias="mfaDetail")

    model_config = {"populate_by_name": True}


class UserRoleAssignment(BaseModel):
    """An Azure RBAC or Entra ID directory role assignment."""

    role_name: str
    role_id: str
    scope: str = ""
    assignment_type: str = "Direct"  # Direct | Inherited | Group
    principal_id: str = ""
    principal_type: str = ""  # User | Group | ServicePrincipal


class ConditionalAccessPolicy(BaseModel):
    """Summary of a conditional access policy affecting the user."""

    policy_id: str
    display_name: str
    state: str  # enabled | disabled | enabledForReportingButNotEnforced
    grant_controls: list[str] = Field(default_factory=list)
    session_controls: list[str] = Field(default_factory=list)


class MFARegistration(BaseModel):
    """MFA / authentication methods registered for a user."""

    is_mfa_registered: bool = False
    is_sspr_registered: bool = False
    is_passwordless_capable: bool = False
    methods_registered: list[str] = Field(default_factory=list)
    last_updated: datetime | None = None


class UserProfile(BaseModel):
    """Core Entra ID user profile."""

    id: str
    display_name: str = Field("", alias="displayName")
    user_principal_name: str = Field("", alias="userPrincipalName")
    mail: str = ""
    job_title: str = Field("", alias="jobTitle")
    department: str = ""
    account_enabled: bool = Field(True, alias="accountEnabled")
    created_date_time: datetime | None = Field(None, alias="createdDateTime")
    last_sign_in: datetime | None = None
    on_premises_sam_account_name: str = Field("", alias="onPremisesSamAccountName")
    on_premises_sync_enabled: bool | None = Field(None, alias="onPremisesSyncEnabled")
    usage_location: str = Field("", alias="usageLocation")
    assigned_licenses: list[str] = Field(default_factory=list, alias="assignedLicenses")

    model_config = {"populate_by_name": True}


class IdentityInvestigationResult(BaseModel):
    """Output of the full identity abuse investigation."""

    user_id: str
    user_principal_name: str
    display_name: str = ""
    profile: UserProfile | None = None
    is_compromised_flag: bool = False
    risk_level: str = "unknown"
    risk_score: float = Field(0.0, ge=0.0, le=10.0)

    # Sign-in analysis
    sign_in_events: list[SignInEvent] = Field(default_factory=list)
    impossible_travel_detected: bool = False
    anomalous_locations: list[str] = Field(default_factory=list)
    failed_mfa_count: int = 0
    successful_mfa_count: int = 0
    legacy_auth_sign_ins: int = 0
    high_risk_sign_ins: int = 0

    # Access & privileges
    role_assignments: list[UserRoleAssignment] = Field(default_factory=list)
    privileged_roles: list[str] = Field(default_factory=list)
    mfa_status: MFARegistration | None = None
    conditional_access_policies: list[ConditionalAccessPolicy] = Field(default_factory=list)

    # Activity indicators
    recent_azure_activity: list[dict[str, Any]] = Field(default_factory=list)
    related_incidents: list[str] = Field(default_factory=list)
    defender_alerts: list[dict[str, Any]] = Field(default_factory=list)

    # Analysis output
    key_findings: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    llm_analysis: str = ""
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
