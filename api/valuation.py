"""
Service de valorisation des sorties de stock (Section 7).

Centralise les trois méthodes configurables (`last_price`, `wac`, `fifo`) et
maintient le registre de couches de coût (`StockCostLayer`). Appelé depuis
`_apply_movement_to_balances()` quand un mouvement passe à `completed`.

Principes :
- Le coût d'un mouvement sortant est calculé serveur et **figé** dans
  `unit_price_at_movement` / `total_cost` au moment de l'exécution.
- Le registre est tenu par article (granularité entreprise, pas dépôt).
- Les transferts inter-sites n'affectent pas le registre.
- Les quantités du registre restent toujours cohérentes quelle que soit la
  méthode active, ce qui permet de changer de méthode en cours de route.
"""
from decimal import Decimal

from django.db.models import F, Sum

from .models import (
    OrganizationSettings,
    StockCostLayer,
    StockMovement,
    StockValuationMethod,
)

ZERO = Decimal("0")


def _active_method() -> str:
    settings_row = OrganizationSettings.objects.first()
    if settings_row is None:
        return StockValuationMethod.WAC
    return settings_row.stock_valuation_method


def _weighted_average_cost(item) -> Decimal:
    """Coût moyen pondéré (CUMP) des couches encore ouvertes pour l'article."""
    agg = StockCostLayer.objects.filter(
        item=item, quantity_remaining__gt=0
    ).aggregate(
        qty=Sum("quantity_remaining"),
        val=Sum(F("quantity_remaining") * F("unit_cost")),
    )
    qty = agg["qty"] or ZERO
    val = agg["val"] or ZERO
    if qty > 0:
        return (val / qty).quantize(Decimal("0.01"))
    return item.unit_price if item.unit_price is not None else ZERO


def open_layer(movement: StockMovement, unit_cost: Decimal) -> None:
    """Ouvre une couche pour un mouvement entrant (entree / retour / ajustement+)."""
    StockCostLayer.objects.create(
        item=movement.item,
        source_movement=movement,
        unit_cost=unit_cost or ZERO,
        quantity_in=movement.quantity,
        quantity_remaining=movement.quantity,
        occurred_at=movement.created_at,
        created_by=movement.created_by,
        updated_by=movement.updated_by,
    )


def consume_layers(item, quantity: Decimal) -> Decimal:
    """
    Consomme `quantity` dans les couches FIFO. Retourne le coût unitaire
    moyen pondéré RÉEL des couches consommées (= coût FIFO).

    Si le registre est vide/insuffisant (cas legacy), complète au dernier
    prix connu de l'article afin de ne pas renvoyer 0 trompeur.
    """
    if quantity is None or quantity <= 0:
        return ZERO
    remaining = quantity
    consumed_value = ZERO
    layers = (
        StockCostLayer.objects.select_for_update()
        .filter(item=item, quantity_remaining__gt=0)
        .order_by("occurred_at")
    )
    for layer in layers:
        if remaining <= 0:
            break
        take = min(layer.quantity_remaining, remaining)
        consumed_value += take * layer.unit_cost
        layer.quantity_remaining -= take
        layer.save(update_fields=["quantity_remaining", "updated_at"])
        remaining -= take
    if remaining > 0:
        fallback = item.unit_price if item.unit_price is not None else ZERO
        consumed_value += remaining * fallback
    return (consumed_value / quantity).quantize(Decimal("0.01"))


def resolve_outgoing_unit_cost(item, quantity: Decimal, method: str) -> Decimal:
    """
    Coût unitaire à figer sur un mouvement sortant, selon la méthode active.

    IMPORTANT : pour `wac` et `last_price`, on consomme quand même les
    couches FIFO (cohérence des quantités du registre) mais on renvoie le
    coût propre à la méthode. Pour `fifo`, le coût est exactement la
    moyenne pondérée réelle des couches consommées.
    """
    if method == StockValuationMethod.WAC:
        cost = _weighted_average_cost(item)
        consume_layers(item, quantity)
        return cost
    if method == StockValuationMethod.LAST_PRICE:
        consume_layers(item, quantity)
        return item.unit_price if item.unit_price is not None else ZERO
    return consume_layers(item, quantity)
