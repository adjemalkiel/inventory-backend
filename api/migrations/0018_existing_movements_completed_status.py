from django.db import migrations


def set_existing_movements_completed(apps, schema_editor):
    StockMovement = apps.get_model("api", "StockMovement")
    StockMovement.objects.filter(reference_number__exact="").update(
        status="completed"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0017_movement_workflow_v2"),
    ]

    operations = [
        migrations.RunPython(
            set_existing_movements_completed,
            migrations.RunPython.noop,
        ),
    ]
