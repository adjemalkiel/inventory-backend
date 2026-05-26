from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0020_normalize_project_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="storagelocation",
            name="city",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="agency",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name="storage_locations",
                to="api.agency",
            ),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name="storage_locations",
                to="api.project",
            ),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="latitude",
            field=models.DecimalField(
                blank=True, decimal_places=6, max_digits=9, null=True
            ),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="longitude",
            field=models.DecimalField(
                blank=True, decimal_places=6, max_digits=9, null=True
            ),
        ),
    ]
