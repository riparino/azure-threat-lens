"""Backward-compatible wrappers for legacy remediation naming.

Prefer `threatlens.models.breach_manager`.
"""

from threatlens.models.breach_manager import (  # noqa: F401
    BreachAction as RemediationAction,
    BreachManagerPlan as BreachRemediationPlan,
    GuidanceLink as GuidanceReference,
)
