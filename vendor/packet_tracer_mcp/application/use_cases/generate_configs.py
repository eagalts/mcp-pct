"""Use case: generar configuraciones CLI."""

from __future__ import annotations
from ...domain.models.plans import TopologyPlan
from ...infrastructure.generator.cli_config_generator import generate_all_configs


def generate_configs_uc(plan: TopologyPlan) -> dict[str, str]:
    """Genera configuraciones CLI por dispositivo."""
    return generate_all_configs(plan)
