"""Extensions to core filters."""

from django_filters import BooleanFilter

try:
    from nautobot.apps.filters import FilterExtension
except ImportError:
    from nautobot.extras.plugins import PluginFilterExtension as FilterExtension


def distinct_filter(queryset, _, value):
    """Returns distinct Inventory Items by part_id."""
    if value:
        return queryset.order_by().distinct("part_id")
    return queryset


class InventoryItemFilterExtension(FilterExtension):  # pylint: disable=too-few-public-methods
    """Extends Inventory Item Filters."""

    model = "dcim.inventoryitem"

    filterset_fields = {
        "nautobot_device_lifecycle_mgmt_distinct_part_id": BooleanFilter(
            method=distinct_filter, label="_dpid_dlm_app_internal_use_only"
        )
    }


filter_extensions = [InventoryItemFilterExtension]
