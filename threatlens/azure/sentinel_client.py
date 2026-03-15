from __future__ import annotations

from threatlens.models.entities import Entity
from threatlens.models.incidents import Alert, Incident


class SentinelClient:
    """Sentinel integration facade; replace with Azure SDK-backed implementation."""

    def get_incident(self, incident_id: str) -> Incident:
        return Incident(
            incident_id=incident_id,
            title=f"Investigation for {incident_id}",
            severity="High",
            alerts=[
                Alert(
                    alert_id="A-001",
                    title="Suspicious sign-in",
                    severity="High",
                    description="Unexpected sign-in activity",
                )
            ],
            entities=[
                Entity(entity_type="identity", name="UPN", value="analyst@contoso.com"),
                Entity(entity_type="ip", name="SourceIP", value="203.0.113.15"),
            ],
        )
