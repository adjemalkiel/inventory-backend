# Generated migration — Section 10.4.3: ApprovalThreshold model

import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("api", "0027_unit_symbol"),
    ]

    operations = [
        migrations.CreateModel(
            name="ApprovalThreshold",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(
                        default=django.utils.timezone.now, editable=False
                    ),
                ),
                ("updated_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "label",
                    models.CharField(
                        help_text="Libellé de la règle (ex : 'Sortie < 100 000 XOF — chef chantier')",
                        max_length=255,
                    ),
                ),
                (
                    "movement_scope",
                    models.CharField(
                        choices=[
                            ("all", "Tous les types"),
                            ("sortie", "Sortie vers chantier"),
                            ("transfert", "Transfert inter-sites"),
                            ("ajustement", "Ajustement / perte"),
                        ],
                        default="all",
                        max_length=32,
                    ),
                ),
                (
                    "min_amount",
                    models.DecimalField(
                        blank=True,
                        decimal_places=2,
                        help_text="Montant minimum (inclus) pour que cette règle s'applique. Vide = 0.",
                        max_digits=14,
                        null=True,
                    ),
                ),
                (
                    "max_amount",
                    models.DecimalField(
                        blank=True,
                        decimal_places=2,
                        help_text="Montant maximum (exclus) pour que cette règle s'applique. Vide = illimité.",
                        max_digits=14,
                        null=True,
                    ),
                ),
                (
                    "required_role_code",
                    models.CharField(
                        help_text="Code du rôle requis pour valider (ex : 'chef_chantier', 'conducteur_travaux', 'administrateur').",
                        max_length=64,
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
                (
                    "order",
                    models.PositiveSmallIntegerField(
                        default=0,
                        help_text="Ordre d'évaluation (ASC). La première règle correspondante s'applique.",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="api_approvalthreshold_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="api_approvalthreshold_updated",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Seuil d'approbation",
                "verbose_name_plural": "Seuils d'approbation",
                "ordering": ["order", "min_amount"],
            },
        ),
    ]
