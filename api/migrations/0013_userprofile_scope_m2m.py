# Périmètre chantiers / emplacements (M2M sur UserProfile)

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0012_alter_userprofile_pref_currency"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="scoped_projects",
            field=models.ManyToManyField(
                blank=True,
                help_text=(
                    "Chantiers assignés : restreint la liste / fiches visibles pour les rôles "
                    "périmètre chantier (ex. chef de chantier). Si vide, repli sur manager / "
                    "conducteur de travaux du projet."
                ),
                related_name="scoped_user_profiles",
                to="api.project",
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="scoped_storage_locations",
            field=models.ManyToManyField(
                blank=True,
                help_text=(
                    "Emplacements de stock assignés : restreint inventaire et mouvements pour "
                    "les rôles périmètre dépôt (ex. magasinier). Si vide, repli sur "
                    "`StorageLocation.manager_user`."
                ),
                related_name="scoped_user_profiles",
                to="api.storagelocation",
            ),
        ),
    ]
