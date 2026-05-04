import django_filters
from django.db.models import F

from .models import Item, StockMovement


class ItemFilter(django_filters.FilterSet):
    """Filtres article ; `stock_status` et `storage_location` complètent les lookups Django."""

    stock_status = django_filters.CharFilter(method="filter_stock_status")
    storage_location = django_filters.UUIDFilter(method="filter_storage_location")

    class Meta:
        model = Item
        fields = ["category", "is_active", "is_consumable", "condition", "supplier"]

    def filter_stock_status(self, queryset, name, value):
        """S’appuie sur l’annotation `total_stock` fournie par `ItemViewSet.get_queryset()`."""
        if value == "stockout":
            return queryset.filter(total_stock__lte=0)
        if value in ("critical", "low"):
            return queryset.filter(total_stock__gt=0, total_stock__lt=F("min_stock"))
        if value == "available":
            return queryset.filter(total_stock__gte=F("min_stock"))
        return queryset

    def filter_storage_location(self, queryset, name, value):
        return queryset.filter(
            balances__storage_location_id=value,
            balances__quantity__gt=0,
        ).distinct()


class StockMovementFilter(django_filters.FilterSet):
    """Filtres liste mouvements : période calendaire ou fenêtre ISO (24h / plage)."""

    date_from = django_filters.DateFilter(field_name="created_at", lookup_expr="date__gte")
    date_to = django_filters.DateFilter(field_name="created_at", lookup_expr="date__lte")
    created_at_after = django_filters.IsoDateTimeFilter(
        field_name="created_at", lookup_expr="gte"
    )
    created_at_before = django_filters.IsoDateTimeFilter(
        field_name="created_at", lookup_expr="lte"
    )

    class Meta:
        model = StockMovement
        fields = ["movement_type", "created_by"]
