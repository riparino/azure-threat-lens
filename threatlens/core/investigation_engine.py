from __future__ import annotations

from collections.abc import Awaitable, Callable

from threatlens.models.investigations import InvestigationReport

InvestigationModule = Callable[[str], Awaitable[InvestigationReport]]


class InvestigationEngine:
    """Pluggable engine that routes investigation requests by module name."""

    def __init__(self) -> None:
        self._modules: dict[str, InvestigationModule] = {}

    def register_module(self, name: str, module: InvestigationModule) -> None:
        self._modules[name] = module

    async def run(self, module_name: str, target: str) -> InvestigationReport:
        if module_name not in self._modules:
            raise ValueError(f"Unknown investigation module: {module_name}")
        return await self._modules[module_name](target)
