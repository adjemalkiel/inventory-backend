# Data migration — Section 10.4.3: Seed default approval thresholds

from django.db import migrations


def seed_thresholds(apps, schema_editor):
    AT = apps.get_model("api", "ApprovalThreshold")
    AT.objects.get_or_create(
        order=1,
        defaults=dict(
            label="Sortie de faible valeur (≤ 50 000 XOF) — chef chantier",
            movement_scope="sortie",
            max_amount="50000",
            required_role_code="chef_chantier",
            is_active=True,
        ),
    )
    AT.objects.get_or_create(
        order=2,
        defaults=dict(
            label="Sortie moyenne valeur (50 000 – 500 000 XOF) — conducteur travaux",
            movement_scope="sortie",
            min_amount="50000",
            max_amount="500000",
            required_role_code="conducteur_travaux",
            is_active=True,
        ),
    )
    AT.objects.get_or_create(
        order=3,
        defaults=dict(
            label="Sortie haute valeur (> 500 000 XOF) — administrateur",
            movement_scope="sortie",
            min_amount="500000",
            required_role_code="administrateur",
            is_active=True,
        ),
    )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0028_approval_threshold"),
    ]

    operations = [
        migrations.RunPython(seed_thresholds, noop),
    ]
