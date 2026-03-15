"""Identity resolver – resolves Entra ID accounts to ResolvedEntity."""

from __future__ import annotations

from threatlens.entities.entity_resolver import score_to_label
from threatlens.models.entities import EntityKind, ResolvedEntity
from threatlens.utils.logging import get_logger

log = get_logger(__name__)

_PRIVILEGED_ROLES = {
    "Global Administrator", "Privileged Role Administrator", "Security Administrator",
    "Exchange Administrator", "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Hybrid Identity Administrator",
}


class IdentityResolver:
    """Resolves an Entra ID account to a ResolvedEntity with risk signals."""

    def __init__(self) -> None:
        from threatlens.azure.graph_client import GraphClient
        self._graph = GraphClient()

    async def resolve(self, identifier: str) -> ResolvedEntity:
        """Resolve a user account (UPN, email, or object ID)."""
        log.info("identity_resolver.resolve", identifier=identifier)

        profile = await self._graph.get_user(identifier)
        if profile is None:
            return ResolvedEntity(
                entity_kind=EntityKind.ACCOUNT,
                identifier=identifier,
                display_name=identifier,
                context={"found": False},
                risk_score=0.0,
                risk_label="Unknown",
                risk_indicators=["User not found in Entra ID"],
            )

        roles = await self._graph.get_directory_roles(profile.id)
        mfa = await self._graph.get_mfa_status(profile.id)

        privileged = [r.role_name for r in roles if r.role_name in _PRIVILEGED_ROLES]
        indicators = []
        risk_score = 0.0

        if not profile.account_enabled:
            indicators.append("Account is disabled in Entra ID")
            risk_score += 2.0

        if not mfa.is_mfa_registered:
            indicators.append("MFA not registered")
            risk_score += 1.5

        if privileged:
            indicators.append(f"Holds privileged roles: {', '.join(privileged)}")
            risk_score += min(len(privileged) * 0.5, 2.0)

        return ResolvedEntity(
            entity_kind=EntityKind.ACCOUNT,
            identifier=profile.user_principal_name,
            display_name=profile.display_name,
            context={
                "user_id": profile.id,
                "job_title": profile.job_title,
                "department": profile.department,
                "account_enabled": profile.account_enabled,
                "mfa_registered": mfa.is_mfa_registered,
                "privileged_roles": privileged,
                "on_prem_sync": profile.on_premises_sync_enabled,
            },
            risk_score=round(min(risk_score, 10.0), 2),
            risk_label=score_to_label(risk_score),
            risk_indicators=indicators,
        )
