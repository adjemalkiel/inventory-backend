# Generated manually — accès lecture utilisateurs pour conducteur (matrice DRF).

from django.db import migrations


def _forwards(apps, schema_editor):
    Permission = apps.get_model("api", "Permission")
    Role = apps.get_model("api", "Role")
    RolePermission = apps.get_model("api", "RolePermission")
    from django.utils import timezone as tz

    p, _ = Permission.objects.update_or_create(
        code="users.view",
        defaults={
            "description": (
                "Consulter la liste des comptes et des profils (lecture seule). "
                "Attribution : conducteur de travaux."
            ),
            "updated_at": tz.now(),
        },
    )
    r = Role.objects.filter(code="conducteur_travaux").first()
    if r is not None:
        RolePermission.objects.get_or_create(
            role=r,
            permission=p,
        )


def _backwards(apps, schema_editor):
    Permission = apps.get_model("api", "Permission")
    Role = apps.get_model("api", "Role")
    RolePermission = apps.get_model("api", "RolePermission")
    p = Permission.objects.filter(code="users.view").first()
    r = Role.objects.filter(code="conducteur_travaux").first()
    if p and r:
        RolePermission.objects.filter(role_id=r.id, permission_id=p.id).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0010_userprofile_password_reset_fields"),
    ]

    operations = [migrations.RunPython(_forwards, _backwards)]

