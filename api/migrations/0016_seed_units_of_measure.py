# Unités courantes pour inventaire BTP / construction (libellés FR).

from django.db import migrations


def seed_units_of_measure(apps, schema_editor):
    UnitOfMeasure = apps.get_model("api", "UnitOfMeasure")
    names = [
        # Quantité / conditionnement
        "pièce",
        "lot",
        "palette",
        "rouleau",
        "sac",
        "seau",
        "bidon",
        "boîte",
        "paquet",
        "bobine",
        "jeu",
        "cartouche",
        "forfait",
        "barre",
        "panneau",
        # Masse
        "g",
        "kg",
        "t",
        # Longueur
        "mm",
        "cm",
        "m",
        "km",
        # Surface / volume
        "m²",
        "m³",
        # Liquides / adjuvants
        "L",
        "ml (liquide)",
        # Location / temps d’utilisation
        "h",
        "jour",
        "semaine",
        "mois",
    ]
    for name in names:
        UnitOfMeasure.objects.get_or_create(name=name)


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0015_seed_categories_inventory_v2"),
    ]

    operations = [
        migrations.RunPython(seed_units_of_measure, migrations.RunPython.noop),
    ]
