from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("dcim", "0027_alter_interface_mac_address"),
        ("nautobot_device_lifecycle_mgmt", "0004_validated_software_m2m"),
    ]

    operations = [
        migrations.AddField(
            model_name="validatedsoftwarelcm",
            name="new_roles",
            field=models.ManyToManyField(
                blank=True, related_name="_validatedsoftwarelcm_new_roles_+", to="extras.Role"
            ),
        ),
        migrations.RenameField(
            model_name="validatedsoftwarelcm",
            old_name="device_roles",
            new_name="legacy_roles",
        ),
    ]
