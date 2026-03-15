"""Compatibility shim.

Legacy `RemediationEngine` maps to `BreachManagerEngine`.
Use `threatlens.core.breach_manager_engine` for new development.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.core.breach_manager_engine import BreachManagerEngine, BreachManagerInput
from threatlens.models.breach_manager import BreachManagerPlan


@dataclass(slots=True)
class RemediationInput:
    scenario: str
    incident: dict | None = None
    alerts: list[dict] | None = None
    entities: list[dict] | None = None


class RemediationEngine:
    async def plan(self, data: RemediationInput) -> BreachManagerPlan:
        engine = BreachManagerEngine()
        return await engine.plan(BreachManagerInput(scenario=data.scenario, incident=data.incident))
