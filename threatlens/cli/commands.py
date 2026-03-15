from __future__ import annotations

import json

from threatlens.azure.sentinel_client import SentinelClient
from threatlens.core.investigation_engine import InvestigationEngine
from threatlens.core.triage_engine import TriageEngine


def emit_report(report: object) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, default=str)


def triage_incident(incident_id: str) -> str:
    sentinel = SentinelClient()
    triage = TriageEngine()
    report = triage.triage_incident(sentinel.get_incident(incident_id))
    return emit_report(report)


def resolve_entity(entity: str) -> str:
    engine = InvestigationEngine()
    report = engine.resolve_entity(entity)
    return emit_report(report)


def investigate_identity(identity: str) -> str:
    engine = InvestigationEngine()
    report = engine.investigate_identity(identity)
    return emit_report(report)


def investigate_resource(resource_id: str) -> str:
    engine = InvestigationEngine()
    report = engine.investigate_resource(resource_id)
    return emit_report(report)
