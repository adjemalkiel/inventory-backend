# Generated migration — Section 10.4.2: Add symbol, description, is_active to UnitOfMeasure

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0026_org_company_profile"),
    ]

    operations = [
        migrations.AddField(
            model_name="unitofmeasure",
            name="symbol",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Symbole court (ex : kg, m³, ml). Affiché dans les tableaux.",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="unitofmeasure",
            name="description",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="unitofmeasure",
            name="is_active",
            field=models.BooleanField(default=True),
        ),
    ]
