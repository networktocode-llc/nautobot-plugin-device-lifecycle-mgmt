# Generated by Django 3.2.25 on 2024-05-01 13:08

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("nautobot_device_lifecycle_mgmt", "0022_migrate_contact_to_core_model"),
    ]

    operations = [
        migrations.AddField(
            model_name="validatedsoftwarelcm",
            name="software_tmp",
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(
            model_name="devicesoftwarevalidationresult",
            name="software_tmp",
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(
            model_name="inventoryitemsoftwarevalidationresult",
            name="software_tmp",
            field=models.UUIDField(null=True),
        ),
        migrations.AddField(model_name="cvelcm", name="software_tmp", field=models.JSONField(default=list, blank=True)),
        migrations.AddField(
            model_name="vulnerabilitylcm",
            name="software_tmp",
            field=models.UUIDField(null=True),
        ),
    ]