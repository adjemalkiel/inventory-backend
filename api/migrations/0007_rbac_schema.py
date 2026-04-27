"""
Migration de schéma : prépare la bascule vers le système RBAC.

- Ajoute `Role.code` (slug stable, requis pour le seed des 8 rôles métier).
- Remplace la contrainte `UNIQUE(user, role)` de `UserRole` par
  `UNIQUE(user)` : un utilisateur ne porte qu'**un seul rôle** à la fois
  dans cette itération. Les multi-rôles seront introduits plus tard.

Le drop de `UserProfile.role` est volontairement reporté à `0009_*` pour
laisser `0008_*` lire la valeur legacy lors du seed des `UserRole`.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_organizationsettings_smtp'),
    ]

    operations = [
        migrations.AddField(
            model_name='role',
            name='code',
            field=models.CharField(
                # Nullable + non-unique pendant la migration : `0008_*` peuple
                # tous les enregistrements puis `0009_*` durcit la contrainte.
                max_length=64,
                null=True,
                blank=True,
            ),
        ),
        migrations.RemoveConstraint(
            model_name='userrole',
            name='uniq_user_role',
        ),
        migrations.AddConstraint(
            model_name='userrole',
            constraint=models.UniqueConstraint(
                fields=('user',),
                name='uniq_user_one_role',
            ),
        ),
    ]
