"""
Module partage de calcul des couts de projet.

Extrait de views.py pour etre importe par alert_engine.py sans
dependance circulaire sur les vues.
"""

from decimal import Decimal
from collections import defaultdict

from django.db.models import Sum, F
from django.db.models.functions import Coalesce
from django.db.models import DecimalField, Value

from .models import (
    Project,
    ProjectBudgetLine,
    ProjectResource,
    StockMovement,
)

_DECIMAL_ZERO_EXPR = Value(
    Decimal("0"), output_field=DecimalField(max_digits=18, decimal_places=2)
)


def _resource_estimated_cost(resource: ProjectResource) -> Decimal:
    if resource.unit_cost is None:
        return Decimal("0")
    if (
        resource.cost_unit == ProjectResource.CostUnit.FORFAIT
        or not resource.planned_duration
    ):
        return resource.unit_cost
    return resource.unit_cost * resource.planned_duration


def compute_project_costs(project: Project) -> dict:
    """
    Consolide les postes de cout d'un chantier (Section 7.3.6).

    Renvoie un dict avec les montants en str (compatible JSON / DRF).
    Utilisee par views.py ET alert_engine.py.
    """
    Z = Decimal("0")

    def _sum(qs, field):
        return qs.aggregate(t=Coalesce(Sum(field), _DECIMAL_ZERO_EXPR))["t"]

    completed = StockMovement.objects.filter(
        project=project,
        status=StockMovement.MovementStatus.COMPLETED,
    )
    cost_materials = _sum(
        completed.filter(movement_type=StockMovement.MovementType.SORTIE),
        "total_cost",
    )
    cost_losses = _sum(
        completed.filter(
            movement_type=StockMovement.MovementType.AJUSTEMENT,
            source_storage_location__isnull=False,
        ),
        "total_cost",
    )

    resources = ProjectResource.objects.filter(project=project)
    cost_labour = Z
    cost_subcontracting = Z
    cost_rental = Z
    for r in resources:
        c = _resource_estimated_cost(r)
        if r.resource_kind == ProjectResource.ResourceKind.MAIN_OEUVRE:
            cost_labour += c
        elif r.resource_kind == ProjectResource.ResourceKind.SUBCONTRACT:
            cost_subcontracting += c
        elif r.resource_kind == ProjectResource.ResourceKind.EQUIPMENT:
            cost_rental += c

    lines = ProjectBudgetLine.objects.filter(project=project)
    cost_overhead = Z
    overhead_categories = (
        ProjectBudgetLine.CostCategory.FRAIS_GENERAUX,
        ProjectBudgetLine.CostCategory.LOGISTIQUE,
    )
    for line in lines.filter(category__in=overhead_categories):
        cost_overhead += (
            line.actual_amount
            if line.actual_amount is not None
            else line.budget_amount
        )

    cost_total = (
        cost_materials
        + cost_losses
        + cost_labour
        + cost_subcontracting
        + cost_rental
        + cost_overhead
    )

    budget_total = project.budget_amount or _sum(lines, "budget_amount")
    contract = project.contract_value
    margin = (contract - cost_total) if contract is not None else None
    margin_percent = None
    if contract is not None and contract > 0 and margin is not None:
        margin_percent = round(float(margin) / float(contract) * 100, 1)
    budget_consumed_percent = None
    if budget_total and budget_total > 0:
        budget_consumed_percent = round(
            float(cost_total) / float(budget_total) * 100, 1
        )

    return {
        "project_id": str(project.id),
        "currency": project.currency,
        "cost_materials": str(cost_materials),
        "cost_losses": str(cost_losses),
        "cost_labour": str(cost_labour),
        "cost_subcontracting": str(cost_subcontracting),
        "cost_rental": str(cost_rental),
        "cost_overhead": str(cost_overhead),
        "cost_total": str(cost_total),
        "budget_total": str(budget_total),
        "budget_consumed_percent": budget_consumed_percent,
        "contract_value": (
            str(contract) if contract is not None else None
        ),
        "margin": str(margin) if margin is not None else None,
        "margin_percent": margin_percent,
    }


def compute_project_costs_simple(project: Project) -> dict:
    """
    Variante allegee ne retournant que cost_total et budget_total
    en Decimal() natif pour alert_engine.py.
    """
    result = compute_project_costs(project)
    return {
        "cost_total": Decimal(result["cost_total"]),
        "budget_total": Decimal(result["budget_total"]),
    }
