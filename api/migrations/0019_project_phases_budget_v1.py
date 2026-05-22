"""
Section 5 — Projets / Chantiers (v1).

Schéma :
- Migre `Project.status` (texte libre) vers `TextChoices` (slugs normalisés).
- Ajoute `progress_percent`, `surface_m2`, `contract_value`, `currency`, `notes` sur Project.
- Crée les modèles `ProjectPhase` et `ProjectBudgetLine`.

Une data migration séparée (0020) normalise les valeurs existantes de `status`.
"""
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0018_existing_movements_completed_status"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # --- Project : nouveaux champs ---
        migrations.AddField(
            model_name="project",
            name="progress_percent",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="project",
            name="surface_m2",
            field=models.DecimalField(
                blank=True, decimal_places=2, max_digits=10, null=True
            ),
        ),
        migrations.AddField(
            model_name="project",
            name="contract_value",
            field=models.DecimalField(
                blank=True, decimal_places=2, max_digits=16, null=True
            ),
        ),
        migrations.AddField(
            model_name="project",
            name="currency",
            field=models.CharField(default="XOF", max_length=8),
        ),
        migrations.AddField(
            model_name="project",
            name="notes",
            field=models.TextField(blank=True),
        ),
        # --- Project.status : élargir d'abord pour permettre la data migration,
        #     la normalisation finale (choices + max_length=32) intervient en 0020.
        migrations.AlterField(
            model_name="project",
            name="status",
            field=models.CharField(
                default="En cours de création", max_length=128
            ),
        ),
        # --- ProjectPhase ---
        migrations.CreateModel(
            name="ProjectPhase",
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
                (
                    "updated_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                ("name", models.CharField(max_length=255)),
                ("order", models.PositiveSmallIntegerField(default=0)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("a_venir", "À venir"),
                            ("en_cours", "En cours"),
                            ("termine", "Terminé"),
                            ("en_retard", "En retard"),
                        ],
                        default="a_venir",
                        max_length=32,
                    ),
                ),
                ("start_date", models.DateField(blank=True, null=True)),
                ("end_date", models.DateField(blank=True, null=True)),
                ("progress_percent", models.PositiveSmallIntegerField(default=0)),
                (
                    "budget_amount",
                    models.DecimalField(
                        blank=True,
                        decimal_places=2,
                        max_digits=16,
                        null=True,
                    ),
                ),
                ("description", models.TextField(blank=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="%(app_label)s_%(class)s_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="%(app_label)s_%(class)s_updated",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="phases",
                        to="api.project",
                    ),
                ),
            ],
            options={
                "ordering": ["project", "order"],
            },
        ),
        migrations.AddConstraint(
            model_name="projectphase",
            constraint=models.UniqueConstraint(
                fields=("project", "order"),
                name="uniq_project_phase_order",
            ),
        ),
        # --- ProjectBudgetLine ---
        migrations.CreateModel(
            name="ProjectBudgetLine",
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
                (
                    "updated_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "category",
                    models.CharField(
                        choices=[
                            ("materiaux", "Matériaux"),
                            ("main_oeuvre", "Main d'œuvre"),
                            ("sous_traitance", "Sous-traitance"),
                            ("location", "Location d'équipements"),
                            ("frais_generaux", "Frais généraux"),
                            ("logistique", "Transport / Logistique"),
                            ("autre", "Autre"),
                        ],
                        max_length=32,
                    ),
                ),
                ("label", models.CharField(blank=True, max_length=255)),
                (
                    "budget_amount",
                    models.DecimalField(decimal_places=2, max_digits=16),
                ),
                (
                    "actual_amount",
                    models.DecimalField(
                        blank=True,
                        decimal_places=2,
                        max_digits=16,
                        null=True,
                    ),
                ),
                ("notes", models.TextField(blank=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="%(app_label)s_%(class)s_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="%(app_label)s_%(class)s_updated",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="budget_lines",
                        to="api.project",
                    ),
                ),
                (
                    "phase",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="budget_lines",
                        to="api.projectphase",
                    ),
                ),
            ],
            options={
                "ordering": ["project", "category", "label"],
            },
        ),
    ]
