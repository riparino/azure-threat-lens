from __future__ import annotations


class ResourceGraphClient:
    """Generic Azure Resource Graph based lookup for any ARM resource type."""

    def get_resource_context(self, resource_id: str) -> dict[str, str]:
        parts = resource_id.strip('/').split('/')
        resource_type = '/'.join(parts[6:8]) if len(parts) >= 8 else 'unknown'
        return {
            "resourceId": resource_id,
            "resourceType": resource_type,
            "subscriptionId": parts[1] if len(parts) > 1 else "unknown",
        }
