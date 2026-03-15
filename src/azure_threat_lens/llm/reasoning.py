"""LLM reasoning engine using the Anthropic Claude API."""

from __future__ import annotations

import json
from typing import Any

import anthropic

from azure_threat_lens.config import get_settings
from azure_threat_lens.logging import get_logger

log = get_logger(__name__)

_DEFAULT_SYSTEM = """You are an expert Microsoft Azure Security Operations analyst with deep
knowledge of Microsoft Sentinel, Entra ID, Defender XDR, and the MITRE ATT&CK framework.
Your role is to help SOC analysts triage incidents, investigate identities, and resolve entity context.
Be concise, precise, and risk-aware. Always cite the evidence from the data provided.
When making recommendations, prioritise containment and evidence preservation.
Format your analysis with clear sections using markdown headers."""


class LLMReasoner:
    """Wraps the Anthropic Claude API for security analysis reasoning."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._cfg = cfg.llm
        self._api_key = cfg.llm.api_key.get_secret_value()
        self._model = cfg.llm.model
        self._max_tokens = cfg.llm.max_tokens
        self._temperature = cfg.llm.temperature
        self._system_persona: str = cfg.get_yaml(
            "llm", "system_persona", default=_DEFAULT_SYSTEM
        )
        self._available = bool(self._api_key)
        if not self._available:
            log.warning("llm.not_configured", hint="Set ATL_ANTHROPIC_API_KEY to enable LLM analysis")

    @property
    def is_available(self) -> bool:
        return self._available

    def _client(self) -> anthropic.Anthropic:
        return anthropic.Anthropic(api_key=self._api_key)

    async def analyse_triage(self, incident_data: dict[str, Any]) -> str:
        """Generate a natural-language triage analysis for an incident."""
        if not self.is_available:
            return _offline_triage_analysis(incident_data)

        prompt = _build_triage_prompt(incident_data)
        return await self._call(prompt, task="triage_analysis")

    async def analyse_identity(self, identity_data: dict[str, Any]) -> str:
        """Generate an identity abuse analysis."""
        if not self.is_available:
            return _offline_identity_analysis(identity_data)

        prompt = _build_identity_prompt(identity_data)
        return await self._call(prompt, task="identity_analysis")

    async def analyse_entity(self, entity_data: dict[str, Any]) -> str:
        """Generate entity risk context analysis."""
        if not self.is_available:
            return _offline_entity_analysis(entity_data)

        prompt = _build_entity_prompt(entity_data)
        return await self._call(prompt, task="entity_analysis")

    async def _call(self, user_message: str, *, task: str = "analysis") -> str:
        """Make a synchronous Claude API call (wrapped for async context)."""
        log.info("llm.call", task=task, model=self._model)
        try:
            client = self._client()
            message = client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=self._system_persona,
                messages=[{"role": "user", "content": user_message}],
            )
            response_text: str = message.content[0].text
            log.info(
                "llm.call.complete",
                task=task,
                input_tokens=message.usage.input_tokens,
                output_tokens=message.usage.output_tokens,
            )
            return response_text
        except anthropic.AuthenticationError:
            log.error("llm.auth_failed", hint="Check ATL_ANTHROPIC_API_KEY")
            return "[LLM analysis unavailable – authentication failed]"
        except anthropic.RateLimitError:
            log.warning("llm.rate_limited")
            return "[LLM analysis unavailable – rate limit exceeded]"
        except Exception as exc:
            log.error("llm.call.failed", error=str(exc))
            return f"[LLM analysis unavailable – {exc}]"


# ── Prompt builders ────────────────────────────────────────────────────────────

def _build_triage_prompt(data: dict[str, Any]) -> str:
    return f"""Analyse the following Microsoft Sentinel incident and provide a structured triage assessment.

## Incident Data
```json
{json.dumps(data, indent=2, default=str)}
```

Please provide:
1. **Executive Summary** – 2-3 sentence overview of what happened
2. **Attack Pattern Assessment** – likely MITRE ATT&CK techniques and kill-chain stage
3. **Risk Assessment** – severity justification with evidence
4. **Immediate Actions** – ordered list of containment/investigation steps
5. **Analyst Notes** – anything unusual or noteworthy

Be specific about the entities involved and the threat indicators observed."""


def _build_identity_prompt(data: dict[str, Any]) -> str:
    return f"""Analyse the following Entra ID identity investigation data for signs of account compromise or insider threat.

## Identity Investigation Data
```json
{json.dumps(data, indent=2, default=str)}
```

Please provide:
1. **Compromise Assessment** – is this account likely compromised? Why?
2. **Behavioural Anomalies** – specific sign-in patterns that indicate risk
3. **Privilege Risk** – assessment of role assignments vs. least-privilege
4. **Timeline of Concern** – key events in chronological order
5. **Recommended Actions** – specific, actionable steps to contain and investigate

Focus on concrete evidence from the data provided."""


def _build_entity_prompt(data: dict[str, Any]) -> str:
    return f"""Analyse the following Azure entity and provide security context.

## Entity Data
```json
{json.dumps(data, indent=2, default=str)}
```

Please provide:
1. **Entity Assessment** – what is this entity and what risk does it pose?
2. **Threat Intelligence Summary** – interpret the TI hits in operational context
3. **Azure Context** – relevance of any Azure resource associations
4. **Recommended Actions** – what should a SOC analyst do with this entity?"""


# ── Offline fallbacks (no LLM key configured) ─────────────────────────────────

def _offline_triage_analysis(data: dict[str, Any]) -> str:
    title = data.get("title", "Unknown Incident")
    severity = data.get("severity", "Unknown")
    tactics = ", ".join(data.get("mitre_tactics", [])) or "unknown"
    return (
        f"**[Offline Mode – LLM not configured]**\n\n"
        f"Incident: **{title}**\n"
        f"Severity: **{severity}**\n"
        f"Tactics: {tactics}\n\n"
        f"Configure `ATL_ANTHROPIC_API_KEY` to enable AI-assisted triage analysis."
    )


def _offline_identity_analysis(data: dict[str, Any]) -> str:
    upn = data.get("user_principal_name", "Unknown")
    risk = data.get("risk_level", "unknown")
    findings = data.get("key_findings", [])
    bullets = "\n".join(f"- {f}" for f in findings) if findings else "- No findings available"
    return (
        f"**[Offline Mode – LLM not configured]**\n\n"
        f"User: **{upn}** | Risk Level: **{risk}**\n\n"
        f"Key Findings:\n{bullets}\n\n"
        f"Configure `ATL_ANTHROPIC_API_KEY` to enable AI-assisted identity analysis."
    )


def _offline_entity_analysis(data: dict[str, Any]) -> str:
    identifier = data.get("identifier", "Unknown")
    kind = data.get("entity_kind", "Unknown")
    risk = data.get("risk_label", "Unknown")
    return (
        f"**[Offline Mode – LLM not configured]**\n\n"
        f"Entity: **{identifier}** ({kind}) | Risk: **{risk}**\n\n"
        f"Configure `ATL_ANTHROPIC_API_KEY` to enable AI-assisted entity analysis."
    )
