"""Azure Resource Graph client – generic cross-subscription resource queries.

The Resource Graph API accepts KQL queries and returns results across ALL
resource types in ALL subscriptions the credential has access to. This is the
correct way to handle environments with thousands of resources.
"""

from __future__ import annotations

from typing import Any

from threatlens.azure._base import BaseAzureClient
from threatlens.utils.config import get_settings
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_ARM = "https://management.azure.com"
_URL = f"{_ARM}/providers/Microsoft.ResourceGraph/resources"
_SCOPE = "https://management.azure.com/.default"
_API = "2021-03-01"


def _kql_str(value: str) -> str:
    """Escape a string value for safe interpolation into a KQL single-quoted literal.

    In KQL, a single quote inside a string literal is represented by doubling it (``''``).
    """
    return value.replace("'", "''")


class ResourceGraphClient(BaseAzureClient):
    """Azure Resource Graph API client.

    Accepts KQL queries and returns structured resource data. Designed to
    handle thousands of Azure resource types generically without needing
    resource-specific API implementations.
    """

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_SCOPE],
        )
        self._sub = cfg.azure.subscription_id

    async def query(
        self,
        kql: str,
        *,
        subscriptions: list[str] | None = None,
        top: int = 100,
    ) -> list[dict[str, Any]]:
        """Execute a KQL query against Azure Resource Graph.

        Args:
            kql:           KQL query string. All standard ARG tables available:
                           Resources, ResourceContainers, SecurityResources, etc.
            subscriptions: Scope to specific subscription IDs; defaults to the
                           configured subscription.
            top:           Maximum rows to return (server-side limit: 1000).
        """
        subs = subscriptions or ([self._sub] if self._sub else [])
        body: dict[str, Any] = {
            "query": kql,
            "options": {"$top": top, "resultFormat": "objectArray"},
        }
        if subs:
            body["subscriptions"] = subs
        log.info("resource_graph.query", preview=kql[:100])
        try:
            data = await self.post(_URL, params={"api-version": _API}, json=body)
            return data.get("data", [])  # type: ignore[return-value,union-attr]
        except Exception as exc:
            log.error("resource_graph.query.failed", error=str(exc))
            return []

    # ── Convenience query builders ─────────────────────────────────────────────

    async def find_by_ip(self, ip: str) -> list[dict[str, Any]]:
        """Find any resource (NIC, public IP, load balancer, etc.) linked to an IP."""
        safe_ip = _kql_str(ip)
        return await self.query(f"""
Resources
| where type in (
    'microsoft.network/publicipaddresses',
    'microsoft.network/networkinterfaces',
    'microsoft.network/loadbalancers'
)
| where properties contains '{safe_ip}'
| project name, type, resourceGroup, subscriptionId, location, properties
| limit 50
""".strip())

    async def find_by_hostname(self, hostname: str) -> list[dict[str, Any]]:
        """Find VMs, App Services, AKS nodes, or DNS records matching a hostname."""
        safe_hostname = _kql_str(hostname)
        return await self.query(f"""
Resources
| where type in (
    'microsoft.compute/virtualmachines',
    'microsoft.web/sites',
    'microsoft.containerservice/managedclusters',
    'microsoft.network/dnszones'
)
| where name contains '{safe_hostname}' or properties contains '{safe_hostname}'
| project name, type, resourceGroup, subscriptionId, location
| limit 50
""".strip())

    async def get_resource(self, resource_id: str) -> dict[str, Any] | None:
        """Fetch full metadata for any resource by its ARM resource ID."""
        safe = _kql_str(resource_id)
        results = await self.query(f"""
Resources
| where id =~ '{safe}'
| project id, name, type, resourceGroup, subscriptionId, location, tags, properties, identity, sku
""".strip(), top=1)
        return results[0] if results else None

    async def find_resources_by_tag(
        self, tag_key: str, tag_value: str | None = None
    ) -> list[dict[str, Any]]:
        """Find resources by tag key/value across all subscriptions."""
        safe_key = _kql_str(tag_key)
        condition = (
            f"tags['{safe_key}'] != ''"
            if tag_value is None
            else f"tags['{safe_key}'] =~ '{_kql_str(tag_value)}'"
        )
        return await self.query(f"""
Resources
| where {condition}
| project name, type, resourceGroup, subscriptionId, location, tags
| limit 200
""".strip())

    async def find_by_type(
        self, resource_type: str, *, top: int = 100
    ) -> list[dict[str, Any]]:
        """List all resources of a given type (e.g., 'microsoft.compute/virtualmachines')."""
        safe_type = _kql_str(resource_type)
        return await self.query(f"""
Resources
| where type =~ '{safe_type}'
| project name, type, resourceGroup, subscriptionId, location, sku, tags
| limit {top}
""".strip(), top=top)

    async def get_vm_details(self, vm_name: str) -> dict[str, Any] | None:
        safe_vm_name = _kql_str(vm_name)
        results = await self.query(f"""
Resources
| where type == 'microsoft.compute/virtualmachines'
| where name contains '{safe_vm_name}'
| project name, resourceGroup, location,
    os=properties.storageProfile.imageReference.offer,
    sku=properties.hardwareProfile.vmSize,
    nics=properties.networkProfile.networkInterfaces,
    tags
| limit 5
""".strip())
        return results[0] if results else None

    async def count_by_type(self) -> list[dict[str, Any]]:
        """Return a count of all resource types – useful for environment overview."""
        return await self.query("""
Resources
| summarize count() by type
| order by count_ desc
| limit 100
""".strip())
