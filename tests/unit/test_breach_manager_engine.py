"""Unit tests for Breach Manager engine."""

from __future__ import annotations

import asyncio

from threatlens.core.breach_manager_engine import BreachManagerEngine, BreachManagerInput


def test_aks_playbook_selected() -> None:
    engine = BreachManagerEngine()
    plan = asyncio.run(
        engine.plan(BreachManagerInput(scenario="AKS compromise with secret theft and workload identity abuse"))
    )

    assert "AKS App-to-Identity Pivot" in plan.selected_playbooks
    assert any(a.phase == "contain" for a in plan.actions)


def test_o365_and_endpoint_scenarios_selected() -> None:
    engine = BreachManagerEngine()
    plan = asyncio.run(
        engine.plan(
            BreachManagerInput(
                scenario="O365 phishing led to endpoint malware beacon and cloud pivot",
                incident={"severity": "High"},
            )
        )
    )

    assert "O365 Phishing to Entra Takeover" in plan.selected_playbooks
    assert "Endpoint Malware to Cloud Pivot" in plan.selected_playbooks
    assert plan.execution_policy == "proposal_only"


def test_multi_tenant_targeting_with_lighthouse() -> None:
    engine = BreachManagerEngine()
    plan = asyncio.run(
        engine.plan(
            BreachManagerInput(
                scenario="vm lateral movement",
                tenant_ids=["tenant-a", "tenant-b"],
                lighthouse=True,
            )
        )
    )

    assert len(plan.tenant_targets) == 2
    assert all(target.lighthouse_delegated for target in plan.tenant_targets)


def test_command_proposals_are_never_auto_executable() -> None:
    engine = BreachManagerEngine()
    plan = asyncio.run(
        engine.plan(
            BreachManagerInput(
                scenario="service principal abuse and role assignment escalation",
            )
        )
    )

    proposals = [p for action in plan.actions for p in action.command_proposals]
    assert proposals
    assert all(not p.auto_executable for p in proposals)


def test_skill_registry_mode_is_in_app() -> None:
    engine = BreachManagerEngine()
    plan = asyncio.run(engine.plan(BreachManagerInput(scenario="generic anomalous behavior")))

    assert plan.skill_registry_mode == "in_app"
    assert plan.skills


def test_local_skill_extends_registry() -> None:
    import os
    from unittest.mock import patch

    payload = '[{"id":"skill.custom.sap","name":"SAP Breach Skill","category":"app","purpose":"SAP incident response","trigger_terms":["sap"],"playbooks_supported":["SAP App Compromise"]}]'
    with patch.dict(os.environ, {"ATL_BM_LOCAL_SKILLS": payload}):
        from threatlens.utils.config import reload_settings

        reload_settings()
        engine = BreachManagerEngine()
        plan = asyncio.run(engine.plan(BreachManagerInput(scenario="sap server compromise")))

        assert "SAP App Compromise" in plan.selected_playbooks
        assert any(skill.id == "skill.custom.sap" for skill in plan.skills)

    from threatlens.utils.config import reload_settings

    reload_settings()
