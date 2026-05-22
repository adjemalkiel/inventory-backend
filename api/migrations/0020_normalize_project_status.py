"""
Section 5 — Normalisation des valeurs `Project.status` vers les slugs `TextChoices`.

Mappe les valeurs texte libres observées vers le vocabulaire ProjectStatus, puis
applique la contrainte de choix + `max_length=32`.
"""
from django.db import migrations, models


STATUS_MAPPING = {
    # Valeurs historiques observées dans le code/seed
    "En cours de création": "brouillon",
    "En cours": "en_cours",
    "Planification": "planification",
    "En planification": "planification",
    "Terminé": "termine",
    "Annulé": "annule",
    "Suspendu": "suspendu",
    # Slugs déjà normalisés : on les conserve tels quels (idempotent)
    "brouillon": "brouillon",
    "planification": "planification",
    "en_cours": "en_cours",
    "suspendu": "suspendu",
    "termine": "termine",
    "annule": "annule",
}

VALID_SLUGS = {
    "brouillon",
    "planification",
    "en_cours",
    "suspendu",
    "termine",
    "annule",
}


def normalize_project_status(apps, schema_editor):
    Project = apps.get_model("api", "Project")
    for project in Project.objects.all():
        current = (project.status or "").strip()
        new_status = STATUS_MAPPING.get(current)
        if new_status is None:
            new_status = "brouillon" if project.is_draft else "en_cours"
        if new_status != project.status:
            project.status = new_status
            project.save(update_fields=["status"])


def noop_reverse(apps, schema_editor):
    # Reverse non-destructif : on garde les slugs (compatibles avec l'ancien CharField libre).
    return None


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0019_project_phases_budget_v1"),
    ]

    operations = [
        migrations.RunPython(normalize_project_status, noop_reverse),
        migrations.AlterField(
            model_name="project",
            name="status",
            field=models.CharField(
                choices=[
                    ("brouillon", "Brouillon"),
                    ("planification", "En planification"),
                    ("en_cours", "En cours"),
                    ("suspendu", "Suspendu"),
                    ("termine", "Terminé"),
                    ("annule", "Annulé"),
                ],
                default="en_cours",
                max_length=32,
            ),
        ),
    ]
