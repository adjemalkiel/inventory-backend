from decimal import Decimal

from django.db import migrations
from django.db.models import Sum


def seed_initial_layers(apps, schema_editor):
    """
    Crée une couche de coût initiale pour chaque article ayant du stock,
    afin de ne pas casser la valorisation des sorties pour les stocks
    existants (legacy avant Section 7).
    """
    Item = apps.get_model("api", "Item")
    StockBalance = apps.get_model("api", "StockBalance")
    StockCostLayer = apps.get_model("api", "StockCostLayer")
    for item in Item.objects.all():
        total = (
            StockBalance.objects.filter(item=item).aggregate(s=Sum("quantity"))[
                "s"
            ]
            or Decimal("0")
        )
        if total > 0:
            cost = item.unit_price if item.unit_price is not None else Decimal("0")
            StockCostLayer.objects.create(
                item=item,
                unit_cost=cost,
                quantity_in=total,
                quantity_remaining=total,
            )


def remove_initial_layers(apps, schema_editor):
    StockCostLayer = apps.get_model("api", "StockCostLayer")
    StockCostLayer.objects.filter(source_movement__isnull=True).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0022_projectresource_costs"),
    ]

    operations = [
        migrations.RunPython(seed_initial_layers, remove_initial_layers),
    ]
