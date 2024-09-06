# Generated by Django 4.2.16 on 2024-11-07 20:28

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("nautobot_device_lifecycle_mgmt", "0026_migrate_soft_references_p3"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="cvelcm",
            name="software_tmp",
        ),
        migrations.RemoveField(
            model_name="devicesoftwarevalidationresult",
            name="software_tmp",
        ),
        migrations.RemoveField(
            model_name="inventoryitemsoftwarevalidationresult",
            name="software_tmp",
        ),
        migrations.RemoveField(
            model_name="validatedsoftwarelcm",
            name="software_tmp",
        ),
        migrations.RemoveField(
            model_name="vulnerabilitylcm",
            name="software_tmp",
        ),
        migrations.AlterField(
            model_name="validatedsoftwarelcm",
            name="software",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="dcim.softwareversion"),
        ),
    ]