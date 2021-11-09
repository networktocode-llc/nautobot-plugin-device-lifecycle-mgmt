"""Filtering implementation for the Lifecycle Management plugin."""
import datetime
import django_filters
from django.db.models import Q

from nautobot.dcim.models import DeviceType, Platform, Device, DeviceRole, InventoryItem
from nautobot.extras.models import Tag
from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    SoftwareLCM,
    ValidatedSoftwareLCM,
    ContractLCM,
    ProviderLCM,
    ContactLCM,
)
from nautobot_device_lifecycle_mgmt.software import DeviceSoftware


class HardwareLCMFilterSet(django_filters.FilterSet):
    """Filter for HardwareLCM."""

    q = django_filters.CharFilter(method="search", label="Search")

    device_type = django_filters.ModelMultipleChoiceFilter(
        field_name="device_type__slug",
        queryset=DeviceType.objects.all(),
        to_field_name="slug",
        label="Device Type (Slug)",
    )
    device_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name="device_type", queryset=DeviceType.objects.all(), label="Device Type"
    )

    inventory_item = django_filters.ModelMultipleChoiceFilter(
        queryset=HardwareLCM.objects.exclude(inventory_item__isnull=True),
        to_field_name="inventory_item",
        field_name="inventory_item",
        label="Inventory Part ID",
    )

    end_of_support = django_filters.DateFilter()
    end_of_support__gte = django_filters.DateFilter(field_name="end_of_support", lookup_expr="gte")
    end_of_support__lte = django_filters.DateFilter(field_name="end_of_support", lookup_expr="lte")

    end_of_sale = django_filters.DateFilter()
    end_of_sale__gte = django_filters.DateFilter(field_name="end_of_sale", lookup_expr="gte")
    end_of_sale__lte = django_filters.DateFilter(field_name="end_of_sale", lookup_expr="lte")

    end_of_security_patches = django_filters.DateFilter()
    end_of_security_patches__gte = django_filters.DateFilter(field_name="end_of_security_patches", lookup_expr="gte")
    end_of_security_patches__lte = django_filters.DateFilter(field_name="end_of_security_patches", lookup_expr="lte")

    end_of_sw_releases = django_filters.DateFilter()
    end_of_sw_releases__gte = django_filters.DateFilter(field_name="end_of_sw_releases", lookup_expr="gte")
    end_of_sw_releases__lte = django_filters.DateFilter(field_name="end_of_sw_releases", lookup_expr="lte")

    expired = django_filters.BooleanFilter(method="expired_search", label="Expired")

    class Meta:
        """Meta attributes for filter."""

        model = HardwareLCM

        fields = [
            "end_of_sale",
            "end_of_support",
            "end_of_sw_releases",
            "end_of_security_patches",
            "inventory_item",
            "documentation_url",
            "expired",
        ]

    def search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        if not value.strip():
            return queryset

        qs_filter = Q(end_of_sale__icontains=value) | Q(end_of_support__icontains=value)
        return queryset.filter(qs_filter)

    def expired_search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        today = datetime.datetime.today().date()
        lookup = "gte" if not value else "lt"

        qs_filter = Q(**{f"end_of_sale__{lookup}": today}) | Q(**{f"end_of_support__{lookup}": today})
        return queryset.filter(qs_filter)


class SoftwareLCMFilterSet(django_filters.FilterSet):
    """Filter for SoftwareLCM."""

    q = django_filters.CharFilter(method="search", label="Search")

    device_platform = django_filters.ModelMultipleChoiceFilter(
        field_name="device_platform__slug",
        queryset=Platform.objects.all(),
        to_field_name="slug",
        label="Device Platform (Slug)",
    )

    release_date = django_filters.DateTimeFromToRangeFilter()
    end_of_support = django_filters.DateTimeFromToRangeFilter()

    class Meta:
        """Meta attributes for filter."""

        model = SoftwareLCM

        fields = [
            "version",
            "alias",
            "documentation_url",
            "download_url",
            "image_file_name",
            "image_file_checksum",
            "long_term_support",
            "pre_release",
        ]

    def search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        if not value.strip():
            return queryset

        qs_filter = (
            Q(version__icontains=value)
            | Q(alias__icontains=value)
            | Q(release_date__icontains=value)
            | Q(end_of_support__icontains=value)
        )
        return queryset.filter(qs_filter)


class ValidatedSoftwareLCMFilterSet(django_filters.FilterSet):
    """Filter for ValidatedSoftwareLCM."""

    q = django_filters.CharFilter(method="search", label="Search")

    software = django_filters.ModelMultipleChoiceFilter(
        queryset=SoftwareLCM.objects.all(),
        label="Software",
    )
    devices_id = django_filters.ModelMultipleChoiceFilter(
        field_name="devices",
        queryset=Device.objects.all(),
        label="Devices",
    )
    devices = django_filters.ModelMultipleChoiceFilter(
        field_name="devices__name",
        queryset=Device.objects.all(),
        to_field_name="name",
        label="Devices (name)",
    )
    device_types_id = django_filters.ModelMultipleChoiceFilter(
        field_name="device_types",
        queryset=DeviceType.objects.all(),
        label="Device Types",
    )
    device_types = django_filters.ModelMultipleChoiceFilter(
        field_name="device_types__model",
        queryset=DeviceType.objects.all(),
        to_field_name="model",
        label="Device Types (model)",
    )
    device_roles_id = django_filters.ModelMultipleChoiceFilter(
        field_name="device_roles",
        queryset=DeviceRole.objects.all(),
        label="Device Roles",
    )
    device_roles = django_filters.ModelMultipleChoiceFilter(
        field_name="device_roles__slug",
        queryset=DeviceRole.objects.all(),
        to_field_name="slug",
        label="Device Roles (slug)",
    )
    inventory_items_id = django_filters.ModelMultipleChoiceFilter(
        field_name="inventory_items",
        queryset=InventoryItem.objects.all(),
        label="Inventory Items",
    )
    inventory_items = django_filters.ModelMultipleChoiceFilter(
        field_name="inventory_items__name",
        queryset=InventoryItem.objects.all(),
        to_field_name="name",
        label="Inventory Items (name)",
    )
    object_tags_id = django_filters.ModelMultipleChoiceFilter(
        field_name="object_tags",
        queryset=Tag.objects.all(),
        label="Object Tags",
    )
    object_tags = django_filters.ModelMultipleChoiceFilter(
        field_name="object_tags__slug",
        queryset=Tag.objects.all(),
        to_field_name="slug",
        label="Object Tags (slug)",
    )
    device_name = django_filters.CharFilter(method="device", label="Device Name")
    device_id = django_filters.CharFilter(method="device", label="Device ID")
    start = django_filters.DateTimeFromToRangeFilter()
    end = django_filters.DateTimeFromToRangeFilter()
    valid = django_filters.BooleanFilter(method="valid_search", label="Currently valid")

    class Meta:
        """Meta attributes for filter."""

        model = ValidatedSoftwareLCM

        fields = [
            "software",
            "devices",
            "device_types",
            "device_roles",
            "inventory_items",
            "object_tags",
            "device_name",
            "device_id",
            "start",
            "end",
            "preferred",
            "valid",
        ]

    def search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        if not value.strip():
            return queryset

        qs_filter = Q(start__icontains=value) | Q(end__icontains=value)
        return queryset.filter(qs_filter)

    def valid_search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the valid_search search."""
        today = datetime.date.today()
        if value is True:
            qs_filter = Q(start__lte=today, end=None) | Q(start__lte=today, end__gte=today)
        else:
            qs_filter = Q(start__gt=today) | Q(end__lt=today)
        return queryset.filter(qs_filter)

    def device(self, queryset, name, value):  # pylint: disable=no-self-use
        """Search for validated software for a given device."""
        value = value.strip()
        if not value:
            return queryset

        if name == "device_name":
            devices = Device.objects.filter(name=value)
        elif name == "device_id":
            devices = Device.objects.filter(id=value)
        else:
            devices = Device.objects.none()

        if devices.count() != 1:
            return queryset.none()

        device = devices.first()
        device_validated_soft = DeviceSoftware(device)

        return device_validated_soft.get_validated_software_qs()


class ContractLCMFilterSet(django_filters.FilterSet):
    """Filter for ContractLCMFilter."""

    q = django_filters.CharFilter(method="search", label="Search")

    provider = django_filters.ModelMultipleChoiceFilter(
        field_name="provider__pk",
        queryset=ProviderLCM.objects.all(),
        to_field_name="pk",
        label="Provider",
    )

    expired = django_filters.BooleanFilter(method="expired_search", label="Expired")

    start = django_filters.DateFilter()
    start__gte = django_filters.DateFilter(field_name="start", lookup_expr="gte")
    start__lte = django_filters.DateFilter(field_name="start", lookup_expr="lte")

    end = django_filters.DateFilter()
    end__gte = django_filters.DateFilter(field_name="end", lookup_expr="gte")
    end__lte = django_filters.DateFilter(field_name="end", lookup_expr="lte")

    class Meta:
        """Meta attributes for filter."""

        model = ContractLCM

        fields = [
            "provider",
            "name",
            "start",
            "end",
            "cost",
            "support_level",
            "contract_type",
            "expired",
        ]

    def search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        if not value.strip():
            return queryset

        qs_filter = (
            Q(name__icontains=value)
            | Q(cost__icontains=value)
            | Q(contract_type__icontains=value)
            | Q(support_level__icontains=value)
        )
        return queryset.filter(qs_filter)

    def expired_search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        today = datetime.datetime.today().date()
        lookup = "gte" if not value else "lt"

        qs_filter = Q(**{f"end__{lookup}": today})
        return queryset.filter(qs_filter)


class ProviderLCMFilterSet(django_filters.FilterSet):
    """Filter for ProviderLCMFilter."""

    q = django_filters.CharFilter(method="search", label="Search")

    class Meta:
        """Meta attributes for filter."""

        model = ProviderLCM

        fields = ProviderLCM.csv_headers

    def search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        if not value.strip():
            return queryset

        qs_filter = (
            Q(name__icontains=value)
            | Q(description__icontains=value)
            | Q(physical_address__icontains=value)
            | Q(phone__icontains=value)
            | Q(email__icontains=value)
        )
        return queryset.filter(qs_filter)


class ContactLCMFilterSet(django_filters.FilterSet):
    """Filter for ContactLCMFilterSet."""

    q = django_filters.CharFilter(method="search", label="Search")

    class Meta:
        """Meta attributes for filter."""

        model = ContactLCM

        fields = ContactLCM.csv_headers

    def search(self, queryset, name, value):  # pylint: disable=unused-argument, no-self-use
        """Perform the filtered search."""
        if not value.strip():
            return queryset

        qs_filter = (
            Q(name__icontains=value)
            | Q(email__icontains=value)
            | Q(phone__icontains=value)
            | Q(address__icontains=value)
        )
        return queryset.filter(qs_filter)
