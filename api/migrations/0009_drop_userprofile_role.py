"""
Migration de schéma finale : abandonne le champ figé `UserProfile.role`.

Le système RBAC (`Role` + `UserRole` + `Permission` + `RolePermission`) est
désormais la **source de vérité unique** pour le rôle utilisateur. Tous les
profils existants ont reçu un `UserRole` correspondant en `0008_*`.

On en profite pour rendre `Role.code` requis (`unique=True`, `blank=False`)
maintenant que toutes les lignes ont été peuplées.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0008_seed_rbac_catalog"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userprofile",
            name="role",
        ),
        migrations.AlterField(
            model_name="role",
            name="code",
            field=models.CharField(max_length=64, unique=True),
        ),
    ]
