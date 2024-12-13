# Generated by Django 3.2.25 on 2024-08-01 15:55

import uuid

import django.core.serializers.json
import django.db.models.deletion
import nautobot.core.models.fields
import nautobot.extras.models.mixins
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0106_populate_default_statuses_and_roles_for_contact_associations"),
        ("dcim", "0058_controller_data_migration"),
        ("nautobot_device_lifecycle_mgmt", "0027_delete_models_migrated_to_core"),
    ]

    operations = [
        migrations.CreateModel(
            name="DeviceHardwareNoticeResult",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "_custom_field_data",
                    models.JSONField(blank=True, default=dict, encoder=django.core.serializers.json.DjangoJSONEncoder),
                ),
                ("is_supported", models.BooleanField(blank=True, null=True)),
                ("last_run", models.DateTimeField(blank=True, null=True)),
                ("run_type", models.CharField(max_length=255)),
                (
                    "device",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="device_hardware_notice",
                        to="dcim.device",
                    ),
                ),
                (
                    "hardware_notice",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="hardware_notice_device",
                        to="nautobot_device_lifecycle_mgmt.hardwarelcm",
                    ),
                ),
                ("tags", nautobot.core.models.fields.TagsField(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={
                "verbose_name": "Device Hardware Notice Report",
                "ordering": ("device",),
            },
            bases=(
                models.Model,
                nautobot.extras.models.mixins.DynamicGroupMixin,
                nautobot.extras.models.mixins.NotesMixin,
            ),
        ),
    ]
