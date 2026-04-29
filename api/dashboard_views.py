"""
Agrégations tableau de bord (Section 2 specs).
Le périmètre par rôle reprend la logique de `access.py` / `scope.py` / `rbac.py`.
"""

from __future__ import annotations

from datetime import date, timedelta, timezone as dt_timezone
from decimal import Decimal
from uuid import UUID

from django.contrib.auth.models import AbstractBaseUser
from django.db.models import Count, F, Q, Sum, Value
from django.db.models.functions import Coalesce
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from . import rbac
from . import scope as user_scope
from .access import project_queryset_for_user
from .models import (
    Item,
    ItemProjectAssignment,
    Project,
    StockBalance,
    StockMovement,
    StorageLocation,
)


def _parse_optional_date(raw: str | None) -> date | None:
    if raw is None or raw == "":
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


def _period_from_request(request) -> tuple[date | None, date | None]:
    """Retourne (date_from, date_to) depuis query params, ou (None, None)."""
    d_from = _parse_optional_date(request.query_params.get("date_from"))
    d_to = _parse_optional_date(request.query_params.get("date_to"))
    if request.query_params.get("date_from") and d_from is None:
        raise ValueError("date_from invalide — utiliser ISO (AAAA-MM-JJ).")
    if request.query_params.get("date_to") and d_to is None:
        raise ValueError("date_to invalide — utiliser ISO (AAAA-MM-JJ).")
    if d_from and d_to and d_from > d_to:
        raise ValueError("date_from doit précéder date_to.")
    return d_from, d_to


def _user_display(user: AbstractBaseUser | None) -> str:
    if user is None:
        return ""
    fn = ""
    getter = getattr(user, "get_full_name", None)
    if callable(getter):
        fn = getter() or ""
    if isinstance(fn, str) and fn.strip():
        return fn.strip()
    username = getattr(user, "username", "") or ""
    return str(username)


def _magasinier_location_ids(user: AbstractBaseUser) -> list[UUID]:
    sids = user_scope.user_scoped_storage_location_ids(user)
    if sids is not None:
        return list(sids)
    return list(
        StorageLocation.objects.filter(manager_user_id=user.id).values_list(
            "id", flat=True
        )
    )


def _ouvrier_derived_location_ids(user: AbstractBaseUser) -> list[UUID]:
    loc_ids = set()
    qs = StockMovement.objects.filter(created_by_id=user.pk)
    for row in qs.values_list(
        "source_storage_location_id", "destination_storage_location_id"
    ):
        for lid in row:
            if lid is not None:
                loc_ids.add(lid)
    return list(loc_ids)


def _ouvrier_location_ids(user: AbstractBaseUser) -> list[UUID]:
    sids = user_scope.user_scoped_storage_location_ids(user)
    if sids is not None:
        return list(sids)
    return _ouvrier_derived_location_ids(user)


def _is_global_dashboard_role(role: str | None, user: AbstractBaseUser) -> bool:
    if rbac.is_admin(user) or getattr(user, "is_superuser", False):
        return True
    if role in (
        "conducteur_travaux",
        "comptable",
        "controleur_gestion",
        "responsable_achats",
    ):
        return True
    return False


def _chef_project_ids(user: AbstractBaseUser) -> list[UUID]:
    return list(project_queryset_for_user(user, Project.objects.all()).values_list("id", flat=True))


def _chef_scoped_item_ids(user: AbstractBaseUser) -> list[UUID]:
    pids = _chef_project_ids(user)
    if not pids:
        return []
    qs = StockMovement.objects.filter(project_id__in=pids).values_list("item_id", flat=True)
    qs2 = ItemProjectAssignment.objects.filter(project_id__in=pids).values_list(
        "item_id", flat=True
    )
    return list(set(qs).union(set(qs2)))


def scoped_item_queryset(user: AbstractBaseUser):
    """QuerySet<Item> pour les KPIs catalogue (filtrés is_active dans les comptages)."""
    role = rbac.get_user_role_code(user)
    base = Item.objects.all()
    if _is_global_dashboard_role(role, user):
        return base

    if role == "chef_chantier":
        ids = _chef_scoped_item_ids(user)
        if not ids:
            return base.none()
        return base.filter(id__in=ids)

    if role == "magasinier":
        lids = _magasinier_location_ids(user)
        if not lids:
            return base.none()
        return base.filter(balances__storage_location_id__in=lids).distinct()

    if role == "ouvrier_technicien":
        lids = _ouvrier_location_ids(user)
        if lids:
            return base.filter(balances__storage_location_id__in=lids).distinct()
        return base.filter(movements__created_by_id=user.pk).distinct()

    return base.none()


def _annotate_total_for_critical_and_stockouts(
    user: AbstractBaseUser, item_qs, role: str | None
):
    """
    Retourne (QuerySet<Item> annotated avec total Decimal) où total reflète la somme des soldes pertinentes au scope dépôt.
    """
    lids: list[UUID] | None = None
    if role == "magasinier":
        lids = _magasinier_location_ids(user)
        if not lids:
            return item_qs.annotate(
                total=Value(Decimal("0")),
            )

    annotated = item_qs
    sum_expr = Sum("balances__quantity")

    if role == "magasinier" and lids is not None:
        sum_expr = Sum(
            "balances__quantity",
            filter=Q(balances__storage_location_id__in=lids),
        )

    return annotated.annotate(
        total=Coalesce(sum_expr, Value(Decimal("0"))),
    )


def scoped_movements_queryset(user: AbstractBaseUser):
    qs = StockMovement.objects.all().select_related(
        "item",
        "source_storage_location",
        "destination_storage_location",
        "project",
        "created_by",
    )
    role = rbac.get_user_role_code(user)
    if rbac.is_admin(user) or getattr(user, "is_superuser", False):
        return qs

    if role is None:
        return StockMovement.objects.none()

    if _is_global_dashboard_role(role, user):
        return qs

    if role == "chef_chantier":
        pids = _chef_project_ids(user)
        if not pids:
            return StockMovement.objects.none()
        return qs.filter(project_id__in=pids)

    if role == "magasinier":
        lids = _magasinier_location_ids(user)
        if not lids:
            return StockMovement.objects.none()
        return qs.filter(
            Q(source_storage_location_id__in=lids)
            | Q(destination_storage_location_id__in=lids)
        )

    if role == "ouvrier_technicien":
        lids = _ouvrier_location_ids(user)
        if lids:
            return qs.filter(
                Q(source_storage_location_id__in=lids)
                | Q(destination_storage_location_id__in=lids)
            )
        return qs.filter(created_by_id=user.pk)

    return StockMovement.objects.none()


def _visible_storage_locations_qs(user: AbstractBaseUser):
    """Emplacements visibles pour la répartition des stocks."""
    qs = StorageLocation.objects.filter(is_active=True)
    role = rbac.get_user_role_code(user)
    if rbac.is_admin(user) or getattr(user, "is_superuser", False):
        return qs

    if role is None:
        return StorageLocation.objects.none()

    if _is_global_dashboard_role(role, user):
        return qs

    if role == "magasinier":
        lids = _magasinier_location_ids(user)
        if lids:
            return qs.filter(id__in=lids)
        return StorageLocation.objects.none()

    if role == "chef_chantier":
        pids = _chef_project_ids(user)
        if not pids:
            return StorageLocation.objects.none()
        item_ids = _chef_scoped_item_ids(user)
        loc_from_balances = StockBalance.objects.filter(item_id__in=item_ids).values_list(
            "storage_location_id", flat=True
        )
        loc_from_mv = StockMovement.objects.filter(project_id__in=pids).values_list(
            "source_storage_location_id", "destination_storage_location_id"
        )
        loc_ids: set[UUID] = set(loc_from_balances)
        for s, d in loc_from_mv:
            if s:
                loc_ids.add(s)
            if d:
                loc_ids.add(d)
        if not loc_ids:
            return StorageLocation.objects.none()
        return qs.filter(id__in=loc_ids)

    if role == "ouvrier_technicien":
        lids = _ouvrier_location_ids(user)
        if lids:
            return qs.filter(id__in=lids)
        return StorageLocation.objects.none()

    return StorageLocation.objects.none()


def _movement_created_at_iso(m: StockMovement) -> str:
    dt = m.created_at
    if dt is None:
        return ""
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    dt = dt.astimezone(dt_timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
    user = request.user
    role = rbac.get_user_role_code(user)

    try:
        d_from, d_to = _period_from_request(request)
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    active_items_qs = scoped_item_queryset(user).filter(is_active=True)

    iq = Item.objects.filter(
        pk__in=active_items_qs.values("pk"),
    )
    iq_annotated = _annotate_total_for_critical_and_stockouts(user, iq, role)
    iq_annotated = iq_annotated.filter(is_active=True)

    critical_stock_count = iq_annotated.filter(
        total__gt=0,
        total__lt=F("min_stock"),
    ).count()

    stockout_count = iq_annotated.filter(total__lte=0).count()

    mv_base = scoped_movements_queryset(user)
    mv_base = mv_base.exclude(created_at=None)

    today = timezone.localdate()
    if d_from and d_to:
        movements_filters = mv_base.filter(
            created_at__date__gte=d_from,
            created_at__date__lte=d_to,
        )
        movements_today = movements_filters.filter(created_at__date=d_to).count()
        movements_week = movements_filters.count()
    else:
        week_start = today - timedelta(days=today.weekday())
        movements_today = mv_base.filter(created_at__date=today).count()
        movements_week = mv_base.filter(
            created_at__date__gte=week_start,
            created_at__date__lte=today,
        ).count()

    active_projects_qs = Project.objects.filter(is_draft=False)
    if rbac.is_admin(user) or getattr(user, "is_superuser", False) or role in (
        "conducteur_travaux",
        "comptable",
        "controleur_gestion",
        "responsable_achats",
    ):
        active_projects = active_projects_qs.count()
    elif role == "chef_chantier":
        active_projects = project_queryset_for_user(user, active_projects_qs).count()
    elif role == "magasinier":
        lids = _magasinier_location_ids(user)
        if lids:
            active_projects = (
                active_projects_qs.filter(
                    Q(stock_movements__source_storage_location_id__in=lids)
                    | Q(stock_movements__destination_storage_location_id__in=lids)
                )
                .distinct()
                .count()
            )
        else:
            active_projects = 0
    elif role == "ouvrier_technicien":
        active_projects = (
            active_projects_qs.filter(stock_movements__created_by_id=user.pk)
            .distinct()
            .count()
        )
    else:
        active_projects = 0

    items_tracked = active_items_qs.count()

    most_critical_item_name = (
        iq_annotated.filter(total__gt=0, total__lt=F("min_stock"))
        .annotate(urgency=F("min_stock") - F("total"))
        .order_by("-urgency")
        .values_list("name", flat=True)
        .first()
    )

    mv_for_busiest = scoped_movements_queryset(user)
    seven_days_ago = today - timedelta(days=7)
    busiest_qs = (
        mv_for_busiest.exclude(project_id=None)
        .filter(created_at__date__gte=seven_days_ago, created_at__date__lte=today)
        .values("project_id")
        .annotate(n=Count("id"))
        .order_by("-n")
        .first()
    )
    busiest_project_last_7_days = None
    if busiest_qs:
        busiest_project_last_7_days = (
            Project.objects.filter(pk=busiest_qs["project_id"])
            .values_list("name", flat=True)
            .first()
        )

    payload = {
        "items_tracked": items_tracked,
        "critical_stock_count": critical_stock_count,
        "stockout_count": stockout_count,
        "movements_today": movements_today,
        "movements_week": movements_week,
        "active_projects": active_projects,
        "total_stock_value": None,
        "total_budget": None,
        "total_cost_consumed": None,
        "unreturned_equipment": None,
        "most_critical_item_name": most_critical_item_name,
        "busiest_project_last_7_days": busiest_project_last_7_days,
    }
    return Response(payload)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_stock_distribution(request):
    user = request.user

    # Valide date_from/date_to si fournis (aligné sur summary / recent-movements).
    # Les soldes restent un instantané courant ; paramètres réservés extensions (ex. stock à date).
    try:
        _period_from_request(request)
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    loc_qs = _visible_storage_locations_qs(user).order_by("name")

    loc_list = list(loc_qs)
    if not loc_list:
        return Response({"locations": []})

    loc_ids = [loc.id for loc in loc_list]
    qty_sums = (
        StockBalance.objects.filter(storage_location_id__in=loc_ids)
        .values("storage_location_id")
        .annotate(qty_sum=Coalesce(Sum("quantity"), Value(Decimal("0"))))
    )
    qty_by_loc = {row["storage_location_id"]: row["qty_sum"] for row in qty_sums}

    critical_by_loc: dict[UUID, int] = {lid: 0 for lid in loc_ids}
    items_at_loc = StockBalance.objects.filter(storage_location_id__in=loc_ids).values_list(
        "storage_location_id", "item_id", flat=False
    )
    pairs = list(items_at_loc)
    item_seen: dict[UUID, set[UUID]] = {lid: set() for lid in loc_ids}
    for lid, item_id in pairs:
        item_seen[lid].add(item_id)

    for loc in loc_list:
        item_ids_here = item_seen.get(loc.id, set())
        if not item_ids_here:
            continue
        item_q = Item.objects.filter(id__in=item_ids_here, is_active=True)
        item_q = item_q.annotate(
            loc_total=Coalesce(
                Sum(
                    "balances__quantity",
                    filter=Q(balances__storage_location_id=loc.id),
                ),
                Value(Decimal("0")),
            )
        )
        crit_n = item_q.filter(
            loc_total__gt=0,
            loc_total__lt=F("min_stock"),
        ).count()
        critical_by_loc[loc.id] = crit_n

    counts = [float(qty_by_loc.get(loc.id, Decimal("0"))) for loc in loc_list]
    max_count = max(counts) if counts else 0.0

    out = []
    for loc in loc_list:
        total_items_count = qty_by_loc.get(loc.id, Decimal("0"))
        max_c = max_count if max_count > 0 else 1.0
        fill = int(round((float(total_items_count) / max_c) * 100))
        out.append(
            {
                "id": str(loc.id),
                "name": loc.name,
                "storage_type": loc.storage_type,
                "total_items_count": float(total_items_count),
                "total_value": None,
                "critical_count": critical_by_loc.get(loc.id, 0),
                "fill_percent": fill,
            }
        )
    return Response({"locations": out})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_recent_movements(request):
    user = request.user
    try:
        d_from, d_to = _period_from_request(request)
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    qs = scoped_movements_queryset(user)
    if d_from and d_to:
        qs = qs.filter(created_at__date__gte=d_from, created_at__date__lte=d_to)
    qs = qs.order_by("-created_at")[:10]

    movements = []
    for m in qs:
        created = m.created_by
        movements.append(
            {
                "id": str(m.id),
                "movement_type": m.movement_type,
                "item_name": m.item.name,
                "item_sku": m.item.sku,
                "quantity": format(m.quantity, "f"),
                "source_location_name": m.source_storage_location.name
                if m.source_storage_location
                else None,
                "destination_location_name": m.destination_storage_location.name
                if m.destination_storage_location
                else None,
                "project_name": m.project.name if m.project else None,
                "created_at": _movement_created_at_iso(m),
                "created_by_name": _user_display(created),
            }
        )
    return Response({"movements": movements})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_cost_overview(request):
    return Response(status=status.HTTP_501_NOT_IMPLEMENTED)
