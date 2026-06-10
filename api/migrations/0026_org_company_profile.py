# Generated migration — Section 10.4.1: Company profile fields on OrganizationSettings

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0024_alert_settings_and_model"),
    ]

    operations = [
        migrations.AddField(
            model_name="organizationsettings",
            name="company_name",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Nom légal de l'entreprise (affiché sur les exports et les emails).",
                max_length=255,
            ),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_logo",
            field=models.ImageField(
                blank=True,
                help_text="Logo de l'entreprise (PNG/JPG, max 2 Mo, ratio paysage recommandé).",
                null=True,
                upload_to="logos/",
            ),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_address",
            field=models.CharField(blank=True, default="", max_length=512),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_city",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_country",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_phone",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_email",
            field=models.EmailField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_website",
            field=models.URLField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="organizationsettings",
            name="company_tax_id",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Numéro d'identification fiscale / RCCM.",
                max_length=128,
            ),
        ),
    ]
