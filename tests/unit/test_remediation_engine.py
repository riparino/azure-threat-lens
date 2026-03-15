"""Backward compatibility tests for legacy remediation engine entrypoint."""

from __future__ import annotations

import asyncio

from threatlens.core.remediation_engine import RemediationEngine, RemediationInput


def test_legacy_remediation_engine_maps_to_breach_manager() -> None:
    plan = asyncio.run(
        RemediationEngine().plan(
            RemediationInput(scenario="AKS compromise with secret theft and role assignment abuse")
        )
    )

    assert plan.selected_playbooks
    assert plan.operation_name == "Azure Breach Manager"
