"""Unit tests for the incident triage analyser."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from azure_threat_lens.models.entity import ThreatIntelHit
from azure_threat_lens.models.incident import Alert, AlertEntity, Incident, Severity


def _make_incident(severity: str = "High", tactics: list[str] | None = None) -> Incident:
    return Incident.model_validate(
        {
            "incidentId": "test-inc",
            "incidentNumber": 1,
            "severity": severity,
            "title": "Test Incident",
            "tactics": tactics or ["Execution"],
        }
    )


def _make_ip_entity(address: str = "198.51.100.1") -> AlertEntity:
    return AlertEntity.model_validate(
        {"entityType": "Ip", "friendlyName": address, "properties": {"address": address}}
    )


@pytest.fixture
def analyser():
    """Create an IncidentTriageAnalyser with Azure clients mocked out."""
    with (
        patch("azure_threat_lens.analysis.triage.SentinelClient") as mock_sentinel,
        patch("azure_threat_lens.analysis.triage.ThreatIntelEnricher") as mock_ti,
    ):
        mock_sentinel.return_value = MagicMock()
        mock_ti.return_value = MagicMock()
        from azure_threat_lens.analysis.triage import IncidentTriageAnalyser
        return IncidentTriageAnalyser()


class TestTriageScoring:
    def test_score_high_severity(self, analyser) -> None:
        inc = _make_incident("High")
        score = analyser._compute_score(inc, [], [], {})
        assert score > 0.0

    def test_score_informational(self, analyser) -> None:
        inc = _make_incident("Informational")
        score = analyser._compute_score(inc, [], [], {})
        high_score = analyser._compute_score(_make_incident("High"), [], [], {})
        assert score < high_score

    def test_score_with_malicious_ti(self, analyser) -> None:
        inc = _make_incident("High")
        ti = {"198.51.100.1": [ThreatIntelHit(provider="virustotal", malicious=True, score=9.0)]}
        score_with_ti = analyser._compute_score(inc, [], [_make_ip_entity()], ti)
        score_without_ti = analyser._compute_score(inc, [], [_make_ip_entity()], {})
        assert score_with_ti > score_without_ti

    def test_score_bounded(self, analyser) -> None:
        inc = _make_incident("High")
        alerts = [Alert.model_validate({"systemAlertId": f"a{i}", "severity": "High"}) for i in range(20)]
        entities = [_make_ip_entity() for _ in range(5)]
        ti = {f"ip{i}": [ThreatIntelHit(provider="vt", malicious=True, score=10.0)] for i in range(5)}
        score = analyser._compute_score(inc, alerts, entities, ti)
        assert score <= 10.0
        assert score >= 0.0

    def test_priority_labels(self, analyser) -> None:
        assert analyser._score_to_label(9.0) == "Critical"
        assert analyser._score_to_label(7.0) == "High"
        assert analyser._score_to_label(5.0) == "Medium"
        assert analyser._score_to_label(2.0) == "Low"

    def test_summary_generation(self, analyser) -> None:
        inc = _make_incident("High", tactics=["InitialAccess"])
        alerts = [Alert.model_validate({"systemAlertId": "a1", "severity": "High"})]
        entities = [_make_ip_entity()]
        summary = analyser._build_summary(inc, alerts, entities)
        assert "Ip" in summary
        assert "InitialAccess" in summary

    def test_recommend_actions_for_high_severity(self, analyser) -> None:
        inc = _make_incident("High", tactics=["CredentialAccess"])
        entities = [
            AlertEntity.model_validate({"entityType": "Account", "friendlyName": "alice", "properties": {}}),
        ]
        actions = analyser._recommend_actions(inc, [], entities, {})
        assert any("investigate" in a.lower() or "identity" in a.lower() for a in actions)
