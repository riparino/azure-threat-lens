"""Azure Resource Graph integration for cross-subscription resource queries."""

from __future__ import annotations

from typing import Any

from azure_threat_lens.config import get_settings
from azure_threat_lens.integrations.azure.base import BaseAzureClient
from azure_threat_lens.logging import get_logger

log = get_logger(__name__)

_ARM_BASE = "https://management.azure.com"
_RESOURCE_GRAPH_URL = f"{_ARM_BASE}/providers/Microsoft.ResourceGraph/resources"
_MANAGEMENT_SCOPE = "https://management.azure.com/.default"


class ResourceGraphClient(BaseAzureClient):
    """Client for Azure Resource Graph – runs KQL-like queries across resources."""

    API_VERSION = "2021-03-01"

    def __init__(self) -> None:
        cfg = get_settings()
        super().__init__(
            tenant_id=cfg.azure.tenant_id,
            client_id=cfg.azure.client_id,
            client_secret=cfg.azure.client_secret,
            scopes=[_MANAGEMENT_SCOPE],
            timeout=cfg.get_yaml("azure", "request_timeout", default=30),
        )
        self._subscription_id = cfg.azure.subscription_id

    async def query(
        self,
        kql: str,
        *,
        subscriptions: list[str] | None = None,
        top: int = 100,
    ) -> list[dict[str, Any]]:
        """Execute a KQL query against Azure Resource Graph."""
        subs = subscriptions or ([self._subscription_id] if self._subscription_id else [])
        body: dict[str, Any] = {
            "query": kql,
            "options": {"$top": top, "resultFormat": "objectArray"},
        }
        if subs:
            body["subscriptions"] = subs

        log.info("resource_graph.query", kql_preview=kql[:120])
        try:
            data = await self.post(
                _RESOURCE_GRAPH_URL,
                params={"api-version": self.API_VERSION},
                json=body,
            )
            return data.get("data", [])  # type: ignore[return-value,union-attr]
        except Exception as exc:
            log.error("resource_graph.query.failed", error=str(exc))
            return []

    async def find_resources_by_ip(self, ip: str) -> list[dict[str, Any]]:
        """Find Azure resources (NICs, public IPs) associated with an IP address."""
        kql = f"""
        Resources
        | where type in ('microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces')
        | where properties contains '{ip}'
        | project name, type, resourceGroup, subscriptionId, location, properties
        | limit 20
        """
        return await self.query(kql.strip())

    async def find_resources_by_hostname(self, hostname: str) -> list[dict[str, Any]]:
        """Find Azure VMs, AKS nodes, or App Services matching a hostname."""
        kql = f"""
        Resources
        | where type in (
            'microsoft.compute/virtualmachines',
            'microsoft.web/sites',
            'microsoft.containerservice/managedclusters'
        )
        | where name contains '{hostname}' or properties contains '{hostname}'
        | project name, type, resourceGroup, subscriptionId, location,
                  kind=properties.storageProfile.imageReference.offer
        | limit 20
        """
        return await self.query(kql.strip())

    async def get_resource_by_id(self, resource_id: str) -> dict[str, Any] | None:
        """Fetch metadata for a specific Azure resource by its ARM resource ID."""
        safe_id = resource_id.replace("'", "\\'")
        kql = f"""
        Resources
        | where id == '{safe_id}'
        | project name, type, resourceGroup, subscriptionId, location, tags, properties
        """
        results = await self.query(kql.strip(), top=1)
        return results[0] if results else None

    async def get_vm_details(self, vm_name: str) -> dict[str, Any] | None:
        """Get VM compute details including OS, size, network configuration."""
        kql = f"""
        Resources
        | where type == 'microsoft.compute/virtualmachines'
        | where name contains '{vm_name}'
        | project
            name,
            resourceGroup,
            location,
            os=properties.storageProfile.imageReference.offer,
            sku=properties.hardwareProfile.vmSize,
            nics=properties.networkProfile.networkInterfaces,
            tags
        | limit 5
        """
        results = await self.query(kql.strip())
        return results[0] if results else None
