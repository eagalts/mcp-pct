"""Use case: explicar plan."""

from __future__ import annotations
from ...domain.models.plans import TopologyPlan
from ...domain.services.explainer import explain_plan


def explain_plan_uc(plan: TopologyPlan) -> list[str]:
    """Genera explicaciones del plan."""
    return explain_plan(plan)
