# Generated manually for display preferences

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0004_userprofile_phone"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="pref_currency",
            field=models.CharField(
                choices=[
                    ("EUR", "Euro (€)"),
                    ("XOF", "Franc CFA (BCEAO)"),
                    ("USD", "Dollar (US)"),
                ],
                default="EUR",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="pref_date_format",
            field=models.CharField(
                choices=[
                    ("dmy", "JJ/MM/AAAA"),
                    ("mdy", "MM/JJ/AAAA"),
                    ("ymd", "AAAA-MM-JJ (ISO)"),
                ],
                default="dmy",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="pref_display_density",
            field=models.CharField(
                choices=[
                    ("standard", "Standard (Editorial)"),
                    ("compact", "Compact"),
                    ("comfortable", "Lecture confortable"),
                ],
                default="standard",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="pref_language",
            field=models.CharField(
                choices=[
                    ("fr-FR", "Français (France)"),
                    ("en-US", "English (US)"),
                ],
                default="fr-FR",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="pref_timezone",
            field=models.CharField(
                choices=[
                    ("Europe/Paris", "(GMT+01:00) Paris"),
                    (
                        "Africa/Porto-Novo",
                        "(GMT+01:00) Cotonou / Porto-Novo",
                    ),
                    ("UTC", "UTC"),
                ],
                default="Europe/Paris",
                max_length=64,
            ),
        ),
    ]
