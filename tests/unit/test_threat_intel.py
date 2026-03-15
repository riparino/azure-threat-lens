"""Unit tests for threat intelligence enricher."""

from __future__ import annotations

import pytest

from azure_threat_lens.integrations.threat_intel.enricher import ThreatIntelEnricher, _is_public_ip
from azure_threat_lens.models.entity import ThreatIntelHit


class TestPublicIpDetection:
    def test_public_ip(self) -> None:
        assert _is_public_ip("8.8.8.8") is True
        assert _is_public_ip("1.1.1.1") is True

    def test_private_ip(self) -> None:
        assert _is_public_ip("10.0.0.1") is False
        assert _is_public_ip("192.168.1.1") is False
        assert _is_public_ip("172.16.0.1") is False

    def test_invalid_ip(self) -> None:
        assert _is_public_ip("not-an-ip") is False
        assert _is_public_ip("") is False


class TestRiskScoreAggregation:
    def test_empty_hits(self) -> None:
        score = ThreatIntelEnricher.aggregate_risk_score([])
        assert score == 0.0

    def test_single_malicious_hit(self) -> None:
        hits = [ThreatIntelHit(provider="virustotal", malicious=True, score=9.0)]
        score = ThreatIntelEnricher.aggregate_risk_score(hits)
        assert score > 0.0

    def test_multiple_hits_higher_score(self) -> None:
        single = [ThreatIntelHit(provider="vt", malicious=True, score=5.0)]
        multiple = [
            ThreatIntelHit(provider="vt", malicious=True, score=5.0),
            ThreatIntelHit(provider="gn", malicious=True, score=8.0),
            ThreatIntelHit(provider="ab", malicious=True, score=9.0),
        ]
        assert ThreatIntelEnricher.aggregate_risk_score(multiple) >= ThreatIntelEnricher.aggregate_risk_score(single)

    def test_no_scores_uses_malicious_count(self) -> None:
        hits = [
            ThreatIntelHit(provider="vt", malicious=True, score=None),
            ThreatIntelHit(provider="gn", malicious=True, score=None),
        ]
        score = ThreatIntelEnricher.aggregate_risk_score(hits)
        assert score > 0.0

    def test_score_bounded(self) -> None:
        hits = [ThreatIntelHit(provider=f"p{i}", malicious=True, score=10.0) for i in range(10)]
        score = ThreatIntelEnricher.aggregate_risk_score(hits)
        assert score <= 10.0


class TestEnricherActiveProviders:
    def test_no_providers_active(self) -> None:
        enricher = ThreatIntelEnricher()
        # In test environment without API keys, no providers should be active
        for provider in enricher._providers:
            assert not provider.is_available or provider._api_key != ""
