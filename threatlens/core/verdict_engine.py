"""Verdict engine – produces a final investigation disposition from aggregated evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from threatlens.utils.logging import get_logger

log = get_logger(__name__)


class Disposition(str, Enum):
    TRUE_POSITIVE = "true_positive"
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    BENIGN_POSITIVE = "benign_positive"
    FALSE_POSITIVE = "false_positive"
    UNDETERMINED = "undetermined"


class VerdictSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EvidenceItem(BaseModel):
    source: str
    description: str
    weight: float = Field(ge=0.0, le=1.0)
    supports_malicious: bool


class Verdict(BaseModel):
    incident_id: str
    disposition: Disposition
    severity: VerdictSeverity
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 confidence in disposition")
    summary: str
    supporting_evidence: list[EvidenceItem] = Field(default_factory=list)
    mitigating_evidence: list[EvidenceItem] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class VerdictInput(BaseModel):
    """Aggregated investigation data fed into the verdict engine."""

    incident_id: str
    triage_report: dict[str, Any] = Field(default_factory=dict)
    identity_findings: list[dict[str, Any]] = Field(default_factory=list)
    resource_findings: list[dict[str, Any]] = Field(default_factory=list)
    privilege_findings: list[dict[str, Any]] = Field(default_factory=list)
    token_abuse_findings: list[dict[str, Any]] = Field(default_factory=list)
    threat_intel_hits: list[dict[str, Any]] = Field(default_factory=list)
    defender_alerts: list[dict[str, Any]] = Field(default_factory=list)
    llm_analysis: str | None = None


# ── Scoring weights ────────────────────────────────────────────────────────────

_SIGNAL_WEIGHTS: dict[str, float] = {
    "defender_critical_alert": 0.95,
    "defender_high_alert": 0.80,
    "impossible_travel": 0.75,
    "privilege_escalation": 0.80,
    "token_replay": 0.70,
    "suspicious_consent": 0.65,
    "threat_intel_malicious": 0.85,
    "threat_intel_suspicious": 0.50,
    "sensitive_resource_op": 0.60,
    "lateral_movement": 0.70,
    "mfa_absent": 0.30,
    "orphaned_sp": 0.35,
    "broad_scope_assignment": 0.50,
    "recent_rbac_change": 0.55,
}

_BENIGN_SIGNALS: dict[str, float] = {
    "greynoise_riot": 0.60,       # Known legitimate scanner
    "all_mfa_pass": 0.20,         # All authentications used MFA
    "single_location": 0.15,      # All activity from single known location
    "service_account": 0.20,      # Identified as service account
}


class VerdictEngine:
    """Produces a final verdict/disposition from aggregated investigation evidence."""

    def render(self, data: VerdictInput) -> Verdict:
        """Synchronously produce a verdict from aggregated investigation data."""
        log.info("verdict_engine.render", incident_id=data.incident_id)

        supporting, mitigating = self._collect_evidence(data)
        malicious_score = self._score_evidence(supporting, mitigating)
        disposition, confidence = self._determine_disposition(malicious_score, supporting, mitigating)
        severity = self._map_severity(data, malicious_score)
        actions = _recommend_actions(disposition, severity, data)
        summary = _build_summary(disposition, severity, supporting, mitigating)

        return Verdict(
            incident_id=data.incident_id,
            disposition=disposition,
            severity=severity,
            confidence=round(confidence, 2),
            summary=summary,
            supporting_evidence=supporting,
            mitigating_evidence=mitigating,
            recommended_actions=actions,
        )

    # ── Evidence collection ────────────────────────────────────────────────────

    def _collect_evidence(
        self, data: VerdictInput
    ) -> tuple[list[EvidenceItem], list[EvidenceItem]]:
        supporting: list[EvidenceItem] = []
        mitigating: list[EvidenceItem] = []

        # Defender alerts
        for alert in data.defender_alerts:
            sev = str(alert.get("Severity") or alert.get("severity") or "").lower()
            title = alert.get("Title") or alert.get("title") or "Defender alert"
            if sev == "critical":
                supporting.append(EvidenceItem(
                    source="Defender XDR",
                    description=f"Critical alert: {title}",
                    weight=_SIGNAL_WEIGHTS["defender_critical_alert"],
                    supports_malicious=True,
                ))
            elif sev == "high":
                supporting.append(EvidenceItem(
                    source="Defender XDR",
                    description=f"High-severity alert: {title}",
                    weight=_SIGNAL_WEIGHTS["defender_high_alert"],
                    supports_malicious=True,
                ))

        # Identity findings
        for finding in data.identity_findings:
            findings_text: list[str] = finding.get("findings", [])
            risk_score: float = float(finding.get("risk_score", 0))
            for text in findings_text:
                tl = text.lower()
                if "impossible travel" in tl:
                    supporting.append(EvidenceItem(
                        source="Identity Analysis",
                        description=text,
                        weight=_SIGNAL_WEIGHTS["impossible_travel"],
                        supports_malicious=True,
                    ))
                elif "mfa" in tl and ("absent" in tl or "disabled" in tl or "not" in tl):
                    supporting.append(EvidenceItem(
                        source="Identity Analysis",
                        description=text,
                        weight=_SIGNAL_WEIGHTS["mfa_absent"],
                        supports_malicious=True,
                    ))
                elif risk_score > 5.0:
                    supporting.append(EvidenceItem(
                        source="Identity Analysis",
                        description=text,
                        weight=min(risk_score / 10.0, 0.9),
                        supports_malicious=True,
                    ))

        # Privilege escalation findings
        for finding in data.privilege_findings:
            findings_text = finding.get("findings", [])
            for text in findings_text:
                tl = text.lower()
                if "subscription" in tl or "role assignment" in tl:
                    w = _SIGNAL_WEIGHTS["privilege_escalation"] if "recent" in tl else _SIGNAL_WEIGHTS["broad_scope_assignment"]
                    supporting.append(EvidenceItem(
                        source="Privilege Analysis",
                        description=text,
                        weight=w,
                        supports_malicious=True,
                    ))

        # Token abuse findings
        for finding in data.token_abuse_findings:
            suspicious: list[str] = finding.get("suspicious_consents", [])
            findings_text = finding.get("findings", [])
            for text in suspicious:
                supporting.append(EvidenceItem(
                    source="Token Abuse Analysis",
                    description=text,
                    weight=_SIGNAL_WEIGHTS["suspicious_consent"],
                    supports_malicious=True,
                ))
            for text in findings_text:
                tl = text.lower()
                weight = _SIGNAL_WEIGHTS["orphaned_sp"] if "orphaned" in tl else _SIGNAL_WEIGHTS["suspicious_consent"]
                supporting.append(EvidenceItem(
                    source="Token Abuse Analysis",
                    description=text,
                    weight=weight,
                    supports_malicious=True,
                ))

        # Threat intelligence
        for hit in data.threat_intel_hits:
            if hit.get("malicious"):
                supporting.append(EvidenceItem(
                    source=f"Threat Intel ({hit.get('provider', 'unknown')})",
                    description=f"Malicious indicator: {hit.get('indicator', '')} — {hit.get('categories', [])}",
                    weight=_SIGNAL_WEIGHTS["threat_intel_malicious"],
                    supports_malicious=True,
                ))
            elif hit.get("suspicious"):
                supporting.append(EvidenceItem(
                    source=f"Threat Intel ({hit.get('provider', 'unknown')})",
                    description=f"Suspicious indicator: {hit.get('indicator', '')}",
                    weight=_SIGNAL_WEIGHTS["threat_intel_suspicious"],
                    supports_malicious=True,
                ))
            elif hit.get("riot"):
                mitigating.append(EvidenceItem(
                    source="GreyNoise",
                    description=f"IP classified as benign/RIOT scanner: {hit.get('indicator', '')}",
                    weight=_BENIGN_SIGNALS["greynoise_riot"],
                    supports_malicious=False,
                ))

        # Resource access findings
        for finding in data.resource_findings:
            findings_text = finding.get("findings", [])
            for text in findings_text:
                tl = text.lower()
                if "sensitive operation" in tl or "lateral movement" in tl:
                    supporting.append(EvidenceItem(
                        source="Resource Access Analysis",
                        description=text,
                        weight=_SIGNAL_WEIGHTS["sensitive_resource_op"],
                        supports_malicious=True,
                    ))

        return supporting, mitigating

    def _score_evidence(
        self,
        supporting: list[EvidenceItem],
        mitigating: list[EvidenceItem],
    ) -> float:
        """Compute net malicious score [0-1] using evidence weights."""
        if not supporting and not mitigating:
            return 0.0
        malicious_sum = sum(e.weight for e in supporting)
        benign_sum = sum(e.weight for e in mitigating)
        total = malicious_sum + benign_sum
        return malicious_sum / total if total > 0 else 0.0

    def _determine_disposition(
        self,
        score: float,
        supporting: list[EvidenceItem],
        mitigating: list[EvidenceItem],
    ) -> tuple[Disposition, float]:
        """Map score + evidence to a disposition with confidence."""
        high_confidence_signals = sum(1 for e in supporting if e.weight >= 0.75)

        if score >= 0.80 or high_confidence_signals >= 2:
            return Disposition.TRUE_POSITIVE, min(0.5 + score * 0.5, 0.99)
        if score >= 0.60:
            return Disposition.LIKELY_TRUE_POSITIVE, 0.5 + (score - 0.60) * 1.25
        if score <= 0.15 and len(mitigating) > 0:
            return Disposition.FALSE_POSITIVE, 1.0 - score
        if score <= 0.30 and not supporting:
            return Disposition.BENIGN_POSITIVE, 0.70
        return Disposition.UNDETERMINED, 0.40 + score * 0.30

    def _map_severity(self, data: VerdictInput, score: float) -> VerdictSeverity:
        triage_risk = str(data.triage_report.get("risk_level", "")).lower()
        # Start from triage risk level, then adjust by evidence score
        base_map = {
            "critical": VerdictSeverity.CRITICAL,
            "high": VerdictSeverity.HIGH,
            "medium": VerdictSeverity.MEDIUM,
            "low": VerdictSeverity.LOW,
        }
        base = base_map.get(triage_risk, VerdictSeverity.MEDIUM)
        # Downgrade if evidence is overwhelmingly benign
        if score < 0.20 and base in (VerdictSeverity.HIGH, VerdictSeverity.CRITICAL):
            return VerdictSeverity.MEDIUM
        # Upgrade if strong malicious signals found regardless of triage
        if score >= 0.85 and base == VerdictSeverity.MEDIUM:
            return VerdictSeverity.HIGH
        return base


# ── Pure helper functions ──────────────────────────────────────────────────────

def _recommend_actions(
    disposition: Disposition,
    severity: VerdictSeverity,
    data: VerdictInput,
) -> list[str]:
    actions: list[str] = []

    if disposition in (Disposition.TRUE_POSITIVE, Disposition.LIKELY_TRUE_POSITIVE):
        if severity in (VerdictSeverity.CRITICAL, VerdictSeverity.HIGH):
            actions.append("Escalate to Tier-3 / Incident Response immediately")
            actions.append("Initiate containment: disable affected accounts and revoke sessions")
        else:
            actions.append("Escalate to Tier-2 for further investigation")

        # Context-specific actions
        has_identity = bool(data.identity_findings)
        has_resource = bool(data.resource_findings)
        has_privilege = bool(data.privilege_findings)

        if has_identity:
            actions.append("Revoke all active sessions for affected user (Entra ID > Revoke Sessions)")
            actions.append("Reset user credentials and enforce MFA re-registration")
        if has_privilege:
            actions.append("Audit and revoke suspicious RBAC role assignments")
            actions.append("Review custom role definitions for privilege escalation paths")
        if has_resource:
            actions.append("Rotate Key Vault secrets and storage account access keys if accessed")
            actions.append("Review NSG and firewall rule changes made during incident window")
        if data.token_abuse_findings:
            actions.append("Revoke suspicious OAuth application consents in Entra ID")
            actions.append("Rotate credentials for affected service principals")
        if data.defender_alerts:
            actions.append("Isolate affected machines via Defender for Endpoint")

    elif disposition == Disposition.FALSE_POSITIVE:
        actions.append("Close incident as False Positive with documented justification")
        actions.append("Tune detection rule to reduce alert noise")

    elif disposition == Disposition.BENIGN_POSITIVE:
        actions.append("Document as Benign Positive; confirm with asset owner")
        actions.append("Consider adding exclusion if activity is recurring and expected")

    else:  # UNDETERMINED
        actions.append("Continue investigation — insufficient evidence for a final disposition")
        actions.append("Engage asset owner to validate whether activity was authorised")

    return actions


def _build_summary(
    disposition: Disposition,
    severity: VerdictSeverity,
    supporting: list[EvidenceItem],
    mitigating: list[EvidenceItem],
) -> str:
    disp_label = disposition.value.replace("_", " ").title()
    sev_label = severity.value.title()
    s_count = len(supporting)
    m_count = len(mitigating)

    if not supporting and not mitigating:
        return (
            f"Verdict: {disp_label} ({sev_label}). "
            "No conclusive evidence was available to support or refute malicious activity."
        )

    top_signal = max(supporting, key=lambda e: e.weight).description if supporting else "N/A"
    summary = (
        f"Verdict: {disp_label} ({sev_label}). "
        f"Analysis identified {s_count} supporting signal(s) and {m_count} mitigating factor(s). "
    )
    if supporting:
        summary += f"Strongest signal: {top_signal}."
    return summary
