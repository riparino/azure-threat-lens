from __future__ import annotations

from typing import Any


class EvidenceStore:
    def __init__(self) -> None:
        self._evidence: dict[str, list[dict[str, Any]]] = {}

    def add(self, case_id: str, evidence: dict[str, Any]) -> None:
        self._evidence.setdefault(case_id, []).append(evidence)

    def list(self, case_id: str) -> list[dict[str, Any]]:
        return self._evidence.get(case_id, [])
