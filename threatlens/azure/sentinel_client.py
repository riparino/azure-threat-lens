from __future__ import annotations

from threatlens.models.entities import Entity, EntityType
from threatlens.models.incidents import Alert, Incident


class SentinelClient:
    """Sentinel client abstraction with mockable methods."""

    async def get_incident(self, incident_id: str) -> Incident:
        ip_entity = Entity(entity_id="e1", entity_type=EntityType.ip, value="198.51.100.10")
        alert = Alert(alert_id="a1", title="Suspicious sign-in", severity="high", entities=[ip_entity])
        return Incident(
            incident_id=incident_id,
            title="Potential account compromise",
            severity="high",
            alerts=[alert],
            entities=[ip_entity],
        )
