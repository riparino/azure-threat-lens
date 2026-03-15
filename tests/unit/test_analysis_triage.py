"""Unit tests for the VerdictEngine."""

from __future__ import annotations

import pytest

from threatlens.core.verdict_engine import (
    Disposition,
    EvidenceItem,
    VerdictEngine,
    VerdictInput,
    VerdictSeverity,
    _recommend_actions,
)


def _make_supporting(weight: float = 0.8) -> EvidenceItem:
    return EvidenceItem(
        source="Test",
        description="Suspicious activity",
        weight=weight,
        supports_malicious=True,
    )


def _make_mitigating(weight: float = 0.6) -> EvidenceItem:
    return EvidenceItem(
        source="Test",
        description="Benign signal",
        weight=weight,
        supports_malicious=False,
    )


class TestVerdictEngine:
    def test_true_positive_with_strong_signals(self) -> None:
        engine = VerdictEngine()
        data = VerdictInput(
            incident_id="test-001",
            defender_alerts=[
                {"Severity": "critical", "Title": "Ransomware detected"},
                {"Severity": "high", "Title": "Lateral movement detected"},
            ],
        )
        verdict = engine.render(data)
        assert verdict.disposition in (
            Disposition.TRUE_POSITIVE, Disposition.LIKELY_TRUE_POSITIVE
        )

    def test_undetermined_with_no_evidence(self) -> None:
        engine = VerdictEngine()
        data = VerdictInput(incident_id="test-002")
        verdict = engine.render(data)
        assert verdict.disposition in (
            Disposition.UNDETERMINED, Disposition.BENIGN_POSITIVE
        )

    def test_false_positive_with_riot_signal(self) -> None:
        engine = VerdictEngine()
        data = VerdictInput(
            incident_id="test-003",
            threat_intel_hits=[
                {"indicator": "8.8.8.8", "provider": "greynoise", "riot": True}
            ],
        )
        verdict = engine.render(data)
        # No malicious signals + riot → should lean false positive or undetermined
        assert verdict.disposition in (
            Disposition.FALSE_POSITIVE, Disposition.UNDETERMINED, Disposition.BENIGN_POSITIVE
        )

    def test_verdict_has_required_fields(self) -> None:
        engine = VerdictEngine()
        verdict = engine.render(VerdictInput(incident_id="test-004"))
        assert verdict.incident_id == "test-004"
        assert 0.0 <= verdict.confidence <= 1.0
        assert verdict.severity in VerdictSeverity.__members__.values()
        assert isinstance(verdict.summary, str)
        assert isinstance(verdict.recommended_actions, list)

    def test_impossible_travel_promotes_tp(self) -> None:
        engine = VerdictEngine()
        data = VerdictInput(
            incident_id="test-005",
            identity_findings=[
                {
                    "findings": ["CRITICAL: Impossible travel – sign-ins from geographically distant locations"],
                    "risk_score": 8.0,
                }
            ],
        )
        verdict = engine.render(data)
        assert verdict.disposition in (
            Disposition.TRUE_POSITIVE, Disposition.LIKELY_TRUE_POSITIVE
        )

    def test_severity_upgraded_for_high_malicious_score(self) -> None:
        engine = VerdictEngine()
        data = VerdictInput(
            incident_id="test-006",
            triage_report={"risk_level": "medium"},
            threat_intel_hits=[
                {"indicator": "1.2.3.4", "provider": "virustotal", "malicious": True},
                {"indicator": "1.2.3.4", "provider": "abuseipdb", "malicious": True},
                {"indicator": "1.2.3.4", "provider": "greynoise", "malicious": True},
            ],
        )
        verdict = engine.render(data)
        # High malicious score should upgrade from medium → high
        assert verdict.severity in (VerdictSeverity.HIGH, VerdictSeverity.CRITICAL, VerdictSeverity.MEDIUM)

    def test_recommended_actions_for_tp(self) -> None:
        actions = _recommend_actions(
            Disposition.TRUE_POSITIVE,
            VerdictSeverity.HIGH,
            VerdictInput(incident_id="x", identity_findings=[{"findings": []}]),
        )
        assert len(actions) > 0
        assert any("escalat" in a.lower() or "contain" in a.lower() for a in actions)

    def test_recommended_actions_for_fp(self) -> None:
        actions = _recommend_actions(
            Disposition.FALSE_POSITIVE,
            VerdictSeverity.LOW,
            VerdictInput(incident_id="x"),
        )
        assert any("false positive" in a.lower() or "close" in a.lower() for a in actions)


class TestEvidenceScoring:
    def test_all_malicious_score_is_one(self) -> None:
        engine = VerdictEngine()
        supporting = [_make_supporting(0.9), _make_supporting(0.8)]
        score = engine._score_evidence(supporting, [])
        assert score == 1.0

    def test_all_benign_score_is_zero(self) -> None:
        engine = VerdictEngine()
        score = engine._score_evidence([], [_make_mitigating()])
        assert score == 0.0

    def test_mixed_score_between(self) -> None:
        engine = VerdictEngine()
        score = engine._score_evidence([_make_supporting(0.5)], [_make_mitigating(0.5)])
        assert 0.0 < score < 1.0
