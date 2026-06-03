from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
import secrets

from django.db import transaction
from django.db.models import (
    Case,
    CharField,
    Count,
    DecimalField,
    ExpressionWrapper,
    F,
    Q,
    Sum,
    Value,
    When,
)
from django.db.models.functions import Coalesce
from django.utils import timezone
from django.conf import settings
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    ActivityEvent,
    Agency,
    Alert,
    ApprovalRule,
    Category,
    Integration,
    Item,
    ItemProjectAssignment,
    OrganizationSettings,
    Permission,
    Project,
    ProjectBudgetLine,
    ProjectPhase,
    ProjectResource,
    Role,
    RolePermission,
    Site,
    StockBalance,
    StockCostLayer,
    StockMovement,
    StockValuationMethod,
    StorageLocation,
    Supplier,
    UnitOfMeasure,
    UserProfile,
    UserRole,
)
from . import valuation
from . import alert_engine
from .mail import (
    send_password_reset_email,
    send_password_reset_success_email,
    send_user_invitation_email,
    smtp_connection_test_hint,
)
from . import access, rbac
from . import scope as user_scope
from . import project_costs as pcosts
from .filters import ApprovalRuleFilter, ItemFilter, StockMovementFilter
from .permissions import IsAdminRole
from .serializers import (
    ActivityEventSerializer,
    AgencySerializer,
    AlertSerializer,
    ApprovalRuleSerializer,
    CategorySerializer,
    ChangePasswordSerializer,
    IntegrationSerializer,
    InviteUserSerializer,
    ItemListSerializer,
    ItemProjectAssignmentSerializer,
    ItemSerializer,
    MeUpdateSerializer,
    OrganizationSettingsSerializer,
    PermissionSerializer,
    ProjectBudgetLineSerializer,
    ProjectPhaseSerializer,
    ProjectResourceSerializer,
    ProjectSerializer,
    RolePermissionSerializer,
    RoleSerializer,
    SiteSerializer,
    StockBalanceSerializer,
    StockMovementSerializer,
    StorageLocationSerializer,
    SupplierSerializer,
    UnitOfMeasureSerializer,
    UserProfileSerializer,
    UserRoleSerializer,
    UserSerializer,
    build_me_response,
)

User = get_user_model()


MOVEMENT_REFERENCE_PREFIX = {
    "entree": "BE",
    "sortie": "BS",
    "transfert": "BT",
    "retour": "BR",
    "ajustement": "BA",
}


def _generate_movement_reference_number(movement: StockMovement) -> str:
    """Numéro séquentiel mensuel après persistance du mouvement (`BS-YYYY-MM-NNNN`)."""
    prefix = MOVEMENT_REFERENCE_PREFIX.get(movement.movement_type, "BX")
    now = timezone.now()
    year, month = now.year, now.month
    n = StockMovement.objects.filter(
        movement_type=movement.movement_type,
        created_at__year=year,
        created_at__month=month,
    ).count()
    return f"{prefix}-{year}-{month:02d}-{n:04d}"


def _apply_movement_to_balances(movement: StockMovement) -> None:
    """Met à jour les `StockBalance` pour un mouvement (transaction attendue par l’appelant)."""
    if movement.movement_type == StockMovement.MovementType.AJUSTEMENT:
        loc = movement.source_storage_location or movement.destination_storage_location
        if loc is None:
            raise ValidationError(
                {
                    "source_storage_location": (
                        "Un emplacement est requis pour un ajustement."
                    )
                }
            )
        qty = movement.quantity
        audit_user = movement.updated_by or movement.created_by
        balance, _ = StockBalance.objects.select_for_update().get_or_create(
            item=movement.item,
            storage_location=loc,
            zone_label="",
            defaults={
                "quantity": 0,
                "updated_by": audit_user,
                "created_by": audit_user,
            },
        )
        if movement.source_storage_location_id:
            if balance.quantity < qty:
                raise ValidationError(
                    {
                        "quantity": (
                            f"Stock insuffisant dans « {loc.name} » : "
                            f"disponible {balance.quantity}, ajustement demandé {qty}."
                        )
                    }
                )
            balance.quantity -= qty
        else:
            balance.quantity += qty
        balance.updated_by = audit_user
        balance.save(update_fields=["quantity", "updated_at", "updated_by"])
        # --- Alertes pour ajustement ---
        _trigger_alerts_for_movement(movement)
        return

    qty = movement.quantity
    src = movement.source_storage_location
    dst = movement.destination_storage_location
    audit_user = movement.updated_by or movement.created_by

    if src is not None:
        balance, _ = StockBalance.objects.select_for_update().get_or_create(
            item=movement.item,
            storage_location=src,
            zone_label="",
            defaults={
                "quantity": 0,
                "updated_by": audit_user,
                "created_by": audit_user,
            },
        )
        if balance.quantity < qty:
            raise ValidationError(
                {
                    "quantity": (
                        f"Stock insuffisant dans « {src.name} » : "
                        f"disponible {balance.quantity}, demandé {qty}."
                    )
                }
            )
        balance.quantity -= qty
        balance.updated_by = audit_user
        balance.save(update_fields=["quantity", "updated_at", "updated_by"])

    if dst is not None:
        balance, _ = StockBalance.objects.select_for_update().get_or_create(
            item=movement.item,
            storage_location=dst,
            zone_label="",
            defaults={
                "quantity": 0,
                "updated_by": audit_user,
                "created_by": audit_user,
            },
        )
        balance.quantity += qty
        balance.updated_by = audit_user
        balance.save(update_fields=["quantity", "updated_at", "updated_by"])

    _apply_movement_to_cost_layers(movement)
    # --- Alertes ---
    _trigger_alerts_for_movement(movement)


def _apply_movement_to_cost_layers(movement: StockMovement) -> None:
    """
    Met à jour le registre de couches de coût (`StockCostLayer`) et fige
    `unit_price_at_movement` / `total_cost` pour les mouvements sortants,
    selon la méthode de valorisation active (Section 7).

    Les transferts inter-sites n'ont aucun effet sur le registre.
    """
    method = valuation._active_method()
    mtype = movement.movement_type

    if mtype == StockMovement.MovementType.ENTREE:
        price = movement.unit_price_at_movement
        if price is None:
            price = movement.item.unit_price or Decimal("0")
        valuation.open_layer(movement, price)
        if movement.unit_price_at_movement is not None:
            movement.item.unit_price = movement.unit_price_at_movement
            movement.item.save(update_fields=["unit_price", "updated_at"])
        return

    if mtype == StockMovement.MovementType.RETOUR:
        valuation.open_layer(
            movement, valuation._weighted_average_cost(movement.item)
        )
        return

    if mtype == StockMovement.MovementType.AJUSTEMENT:
        if movement.destination_storage_location_id:
            valuation.open_layer(
                movement, movement.item.unit_price or Decimal("0")
            )
            return
        if movement.source_storage_location_id:
            unit_cost = valuation.resolve_outgoing_unit_cost(
                movement.item, movement.quantity, method
            )
            movement.unit_price_at_movement = unit_cost
            movement.total_cost = unit_cost * movement.quantity
            movement.save(
                update_fields=[
                    "unit_price_at_movement",
                    "total_cost",
                    "updated_at",
                ]
            )
        return

    if mtype == StockMovement.MovementType.SORTIE:
        unit_cost = valuation.resolve_outgoing_unit_cost(
            movement.item, movement.quantity, method
        )
        movement.unit_price_at_movement = unit_cost
        movement.total_cost = unit_cost * movement.quantity
        movement.save(
            update_fields=[
                "unit_price_at_movement",
                "total_cost",
                "updated_at",
            ]
        )
        return


def _trigger_alerts_for_movement(movement: StockMovement) -> None:
    """
    Declenche les alertes pertinentes apres completion d'un mouvement.
    Les alertes ne doivent jamais bloquer la transaction principale.
    """
    try:
        alert_engine.check_stock_alerts(movement.item)

        if movement.movement_type == StockMovement.MovementType.ENTREE:
            alert_engine.generate_new_delivery_alert(movement)

        elif movement.movement_type == StockMovement.MovementType.SORTIE:
            alert_engine.generate_abnormal_movement_alert(movement)
            if movement.project:
                alert_engine.check_budget_alert(movement.project)

        elif (movement.movement_type == StockMovement.MovementType.AJUSTEMENT
              and movement.source_storage_location):
            alert_engine.generate_inventory_gap_alert(movement)

    except Exception:
        pass


def _issue_password_reset_for_user(*, user, request) -> tuple[bool, str]:
    """
    Enregistre un jeton sur `UserProfile` et envoie l’e-mail avec le lien
    `/reset-password?reset=…` (usage : « mot de passe oublié » ou action admin).
    """
    profile, _ = UserProfile.objects.get_or_create(user=user)
    raw = secrets.token_urlsafe(48)
    now = timezone.now()
    profile.password_reset_token = raw
    profile.password_reset_sent_at = now
    profile.save(
        update_fields=[
            "password_reset_token",
            "password_reset_sent_at",
            "updated_at",
        ]
    )
    return send_password_reset_email(
        user=user, request=request, reset_token=raw
    )


class SetAuditUsersMixin:
    """Set created_by / updated_by from request.user when authenticated."""

    def perform_create(self, serializer):
        user = (
            self.request.user if self.request.user.is_authenticated else None
        )
        serializer.save(created_by=user, updated_by=user)

    def perform_update(self, serializer):
        user = (
            self.request.user if self.request.user.is_authenticated else None
        )
        serializer.save(updated_by=user)


class SiteViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.SiteViewSetAccess]
    queryset = Site.objects.all()
    serializer_class = SiteSerializer


class UserViewSet(viewsets.ModelViewSet):
    """
    CRUD for Django's built-in User (no custom user model in api.models).
    """

    permission_classes = [IsAuthenticated, access.UsersOrProfilesAccess]
    queryset = User.objects.all().order_by("username")
    serializer_class = UserSerializer

    @action(
        detail=False,
        methods=["post"],
        url_path="invite",
        permission_classes=[IsAuthenticated, IsAdminRole],
    )
    def invite(self, request):
        """
        Créer un utilisateur inactif côté mot de passe, son profil, et envoyer
        l’e-mail d’invitation (lien `/activate` validé par `POST /auth/activate/`
        avec `invite_token` stocké sur le profil).
        """
        ser = InviteUserSerializer(data=request.data, context={"request": request})
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        with transaction.atomic():
            email = d["email"]
            local = (email.split("@")[0] or "user").replace(".", "_")
            local = "".join(c for c in local if c.isalnum() or c in ("_", "-"))[:100] or "user"
            uname = local
            n = 0
            while User.objects.filter(username=uname).exists():
                n += 1
                uname = f"{local}{n}"[:150]

            user = User(
                email=email,
                username=uname,
                first_name=(d.get("first_name") or "").strip()[:150],
                last_name=(d.get("last_name") or "").strip()[:150],
                is_active=True,
                is_staff=False,
            )
            user.set_unusable_password()
            user.save()

            site = None
            if d.get("site"):
                site = Site.objects.get(pk=d["site"])
            prof = UserProfile.objects.create(
                user=user,
                job_title=(d.get("job_title") or "").strip()[:255],
                phone=(d.get("phone") or "").strip()[:64],
                site=site,
                invite_token=secrets.token_urlsafe(48),
                invited_at=timezone.now(),
                created_by=request.user,
                updated_by=request.user,
            )

            # Affecte le rôle RBAC (un seul rôle par utilisateur, contrainte
            # `uniq_user_one_role`). Le slug a été validé par
            # `InviteUserSerializer.role` contre `rbac.get_role_choices()`.
            invited_role = Role.objects.filter(code=d["role"]).first()
            if invited_role is None:
                # Filet de sécurité : la validation a déjà rejeté les codes
                # inconnus, mais on évite un crash 500 si le seed RBAC n'a pas
                # encore tourné dans cet environnement.
                raise serializers.ValidationError(
                    {"role": f"Rôle inconnu : {d['role']}."}
                )
            UserRole.objects.update_or_create(
                user=user,
                defaults={"role": invited_role},
            )

            if "scoped_project_ids" in d:
                prof.scoped_projects.set(
                    Project.objects.filter(id__in=d["scoped_project_ids"])
                )
            if "scoped_storage_location_ids" in d:
                prof.scoped_storage_locations.set(
                    StorageLocation.objects.filter(
                        id__in=d["scoped_storage_location_ids"]
                    )
                )

        fresh = (
            UserProfile.objects.select_related("user", "site")
            .prefetch_related("scoped_projects", "scoped_storage_locations")
            .filter(pk=prof.pk)
            .first()
        )
        sent, delivery = send_user_invitation_email(profile=fresh, request=request)
        return Response(
            {
                "user": UserSerializer(user).data,
                "profile": UserProfileSerializer(fresh).data,
                "invitation_email_sent": sent,
                # Identifiant stable du backend e-mail effectivement utilisé.
                # Ex. « org-smtp » = livré via Paramètres → SMTP ; « console »
                # = simple impression stdout (dev, SMTP non configuré).
                "email_delivery": delivery,
            },
            status=status.HTTP_201_CREATED,
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="resend-invitation",
        permission_classes=[IsAuthenticated, IsAdminRole],
    )
    def resend_invitation(self, request, pk=None):
        """
        Renvoie l’e-mail d’invitation (lien mot de passe) pour un compte qui ne
        s’est jamais connecté.
        """
        user = self.get_object()
        if user.last_login is not None:
            return Response(
                {
                    "detail": "Cet utilisateur s'est déjà connecté ; l'invitation n'est plus nécessaire.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        profile = (
            UserProfile.objects.select_related("user", "site")
            .filter(user_id=user.pk)
            .first()
        )
        if not profile:
            return Response(
                {"detail": "Aucun profil associé à ce compte."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        profile.invited_at = timezone.now()
        profile.invite_token = secrets.token_urlsafe(48)
        profile.updated_by = request.user
        profile.save()
        fresh = (
            UserProfile.objects.select_related("user", "site")
            .filter(pk=profile.pk)
            .first()
        )
        sent, delivery = send_user_invitation_email(profile=fresh, request=request)
        return Response(
            {
                "user": UserSerializer(user).data,
                "profile": UserProfileSerializer(fresh).data,
                "invitation_email_sent": sent,
                "email_delivery": delivery,
            }
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="send-password-reset",
        permission_classes=[IsAuthenticated, IsAdminRole],
    )
    def send_password_reset(self, request, pk=None):
        """
        Envoie à l'utilisateur un e-mail de réinitialisation de mot de passe
        (même lien/template que « mot de passe oublié »). Réservé aux comptes
        actifs et **déclenché par un administrateur** depuis la page Utilisateurs.

        Contrairement à l'endpoint public `/auth/password-reset/request/` qui
        renvoie systématiquement 200 pour éviter l'énumération, ici on est
        authentifié : on remonte une erreur explicite si le compte est inactif
        ou si l'e-mail SMTP a échoué.
        """
        user = self.get_object()
        if not user.is_active:
            return Response(
                {
                    "detail": (
                        "Ce compte est désactivé : réactivez-le avant d'envoyer "
                        "un lien de réinitialisation."
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not (user.email or "").strip():
            return Response(
                {"detail": "Ce compte n'a pas d'adresse e-mail."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        sent, delivery = _issue_password_reset_for_user(user=user, request=request)
        return Response(
            {
                "user": UserSerializer(user).data,
                "password_reset_email_sent": bool(sent),
                "email_delivery": delivery,
            }
        )


class AgencyViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.AgencyProjectScopeAccess]
    queryset = Agency.objects.all()
    serializer_class = AgencySerializer

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_authenticated:
            return qs.none()
        if getattr(u, "is_superuser", False) or rbac.is_admin(u):
            return qs
        r = rbac.get_user_role_code(u)
        if r in access._RO_BLOCK_PROJECT_READ:
            return qs.none()
        if r in (
            "conducteur_travaux",
            "comptable",
            "controleur_gestion",
        ):
            return qs
        pqs = access.project_queryset_for_user(u, Project.objects.all())
        a_ids = pqs.exclude(agency_id__isnull=True).values_list(
            "agency_id", flat=True
        ).distinct()
        return qs.filter(id__in=a_ids)


class StorageLocationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.StorageLocationAccess]
    queryset = StorageLocation.objects.all()
    serializer_class = StorageLocationSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["storage_type", "is_active", "agency", "project"]
    search_fields = ["name", "address", "city", "manager_name"]
    ordering_fields = ["name", "storage_type", "city", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        qs = StorageLocation.objects.select_related(
            "agency", "project", "manager_user"
        ).annotate(
            stock_items_count=Count(
                "stock_balances__item", distinct=True
            ),
            stock_value=Coalesce(
                Sum(
                    F("stock_balances__quantity")
                    * F("stock_balances__item__unit_price"),
                    output_field=DecimalField(max_digits=18, decimal_places=2),
                ),
                Value(0, output_field=DecimalField(max_digits=18, decimal_places=2)),
            ),
            critical_count=Count(
                "stock_balances__item",
                filter=Q(
                    stock_balances__quantity__gt=0,
                    stock_balances__quantity__lt=F("stock_balances__item__min_stock"),
                ),
                distinct=True,
            ),
        )
        u = self.request.user
        r = rbac.get_user_role_code(u)
        if r == "magasinier":
            sids = user_scope.user_scoped_storage_location_ids(u)
            if sids is not None:
                return qs.filter(id__in=sids)
            return qs.filter(manager_user_id=u.id)
        return qs

    @action(detail=True, methods=["get"], url_path="summary")
    def summary(self, request, pk=None):
        """KPIs agrégés pour un lieu de stockage (Section 6.3.3)."""
        location = self.get_object()
        today = timezone.now().date()

        balances_qs = StockBalance.objects.filter(storage_location=location)

        items_count = (
            balances_qs.filter(quantity__gt=0).values("item").distinct().count()
        )

        stock_value = balances_qs.aggregate(
            total=Coalesce(
                Sum(
                    F("quantity") * F("item__unit_price"),
                    output_field=DecimalField(max_digits=18, decimal_places=2),
                ),
                Value(
                    Decimal("0"),
                    output_field=DecimalField(max_digits=18, decimal_places=2),
                ),
            )
        )["total"]

        stockout_count = (
            balances_qs.filter(quantity__lte=0).values("item").distinct().count()
        )

        critical_count = (
            balances_qs.filter(
                quantity__gt=0,
                quantity__lt=F("item__min_stock"),
            )
            .values("item")
            .distinct()
            .count()
        )

        movements_qs = StockMovement.objects.filter(
            Q(source_storage_location=location)
            | Q(destination_storage_location=location)
        )
        movements_today = movements_qs.filter(created_at__date=today).count()
        movements_week = movements_qs.filter(
            created_at__date__gte=today - timedelta(days=7)
        ).count()

        zones = list(
            balances_qs.exclude(zone_label="")
            .values_list("zone_label", flat=True)
            .distinct()
            .order_by("zone_label")
        )

        return Response(
            {
                "location_id": str(location.id),
                "name": location.name,
                "storage_type": location.storage_type,
                "is_active": location.is_active,
                "items_count": items_count,
                "stock_value": str(stock_value),
                "stockout_count": stockout_count,
                "critical_count": critical_count,
                "movements_today": movements_today,
                "movements_week": movements_week,
                "zones": zones,
                "zones_count": len(zones),
                "capacity_m2": (
                    str(location.capacity_m2) if location.capacity_m2 else None
                ),
                "capacity_percent": None,
                "has_coordinates": bool(location.latitude and location.longitude),
            }
        )

    @action(detail=True, methods=["get"], url_path="zones")
    def zones(self, request, pk=None):
        """Liste des zones utilisées dans ce lieu avec stock agrégé."""
        location = self.get_object()

        zones_data = (
            StockBalance.objects.filter(storage_location=location)
            .values("zone_label")
            .annotate(
                items_count=Count("item", distinct=True),
                total_quantity=Coalesce(
                    Sum("quantity"),
                    Value(
                        Decimal("0"),
                        output_field=DecimalField(max_digits=14, decimal_places=3),
                    ),
                ),
            )
            .order_by("zone_label")
        )

        return Response(
            {
                "location_id": str(location.id),
                "zones": [
                    {
                        "zone_label": z["zone_label"] or "",
                        "zone_display": z["zone_label"] or "(Zone principale)",
                        "items_count": z["items_count"],
                        "total_quantity": str(z["total_quantity"]),
                    }
                    for z in zones_data
                ],
            }
        )


class UnitOfMeasureViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.ItemCatalogAccess]
    queryset = UnitOfMeasure.objects.all()
    serializer_class = UnitOfMeasureSerializer


class CategoryViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.ItemCatalogAccess]
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class SupplierViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.ItemCatalogAccess]
    queryset = Supplier.objects.filter(is_active=True)
    serializer_class = SupplierSerializer


class UserProfileViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.UsersOrProfilesAccess]
    queryset = (
        UserProfile.objects.select_related("user", "site")
        .prefetch_related("scoped_projects", "scoped_storage_locations")
        .all()
    )
    serializer_class = UserProfileSerializer


class ItemViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.ItemCatalogAccess]
    serializer_class = ItemSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ItemFilter
    search_fields = [
        "name",
        "sku",
        "description",
        "brand",
        "barcode",
        "serial_number",
    ]
    ordering_fields = ["name", "sku", "created_at", "unit_price", "min_stock"]
    ordering = ["name"]

    def get_serializer_class(self):
        if self.action == "list":
            return ItemListSerializer
        return ItemSerializer

    def get_queryset(self):
        total_qty_expr = Coalesce(
            Sum("balances__quantity"),
            Value(0, output_field=DecimalField(max_digits=14, decimal_places=3)),
        )
        unit_price_or_zero = Coalesce(
            F("unit_price"),
            Value(0, output_field=DecimalField(max_digits=14, decimal_places=2)),
        )
        return (
            Item.objects.select_related("category", "unit", "supplier")
            .annotate(total_stock=total_qty_expr)
            .annotate(
                stock_status=Case(
                    When(total_stock__lte=0, then=Value("stockout")),
                    When(total_stock__lt=F("min_stock"), then=Value("low")),
                    default=Value("available"),
                    output_field=CharField(),
                ),
                stock_value=ExpressionWrapper(
                    F("total_stock") * unit_price_or_zero,
                    output_field=DecimalField(max_digits=16, decimal_places=2),
                ),
            )
        )

    @action(detail=True, methods=["get"], url_path="detail")
    def item_detail(self, request, pk=None):
        item = self.get_object()

        balances = (
            StockBalance.objects.filter(item=item)
            .select_related("storage_location")
            .order_by("storage_location__name")
        )
        movements = (
            StockMovement.objects.filter(item=item)
            .select_related(
                "source_storage_location",
                "destination_storage_location",
                "project",
                "created_by",
            )
            .order_by("-created_at")[:10]
        )
        assignments = (
            ItemProjectAssignment.objects.filter(item=item)
            .select_related("project")
            .order_by("-assigned_at")
        )

        return Response(
            {
                "item": ItemSerializer(item, context={"request": request}).data,
                "balances": StockBalanceSerializer(balances, many=True).data,
                "movements": StockMovementSerializer(movements, many=True).data,
                "assignments": ItemProjectAssignmentSerializer(
                    assignments, many=True
                ).data,
            }
        )

    @action(detail=True, methods=["get"], url_path="price-history")
    def price_history(self, request, pk=None):
        """Historique des prix d'achat + CUMP courant (Section 7.3.8)."""
        item = self.get_object()
        qs = (
            StockMovement.objects.filter(
                item=item,
                movement_type=StockMovement.MovementType.ENTREE,
                unit_price_at_movement__isnull=False,
            )
            .select_related("item__supplier")
            .order_by("-created_at")
            .values(
                "created_at",
                "unit_price_at_movement",
                "quantity",
                "reference_number",
            )
        )
        points = [
            {
                "date": p["created_at"].date().isoformat(),
                "unit_price": str(p["unit_price_at_movement"]),
                "quantity": str(p["quantity"]),
                "reference": p["reference_number"],
            }
            for p in qs
        ]
        prices = [Decimal(pt["unit_price"]) for pt in points]
        wac = valuation._weighted_average_cost(item)
        return Response(
            {
                "item_id": str(item.id),
                "current_price": (
                    str(item.unit_price) if item.unit_price is not None else None
                ),
                "weighted_average_cost": str(wac),
                "min_price": str(min(prices)) if prices else None,
                "max_price": str(max(prices)) if prices else None,
                "points": points,
            }
        )

    @action(detail=False, methods=["get"], url_path="stock-valuation")
    def stock_valuation(self, request):
        """Inventaire valorisé (Section 7.3.9)."""
        method = valuation._active_method()
        rows: list[dict] = []
        grand_total = Decimal("0")
        layer_value_expr = Coalesce(
            Sum(F("quantity_remaining") * F("unit_cost")),
            _DECIMAL_ZERO_EXPR,
        )
        balance_qty_expr = Coalesce(
            Sum("quantity"),
            Value(
                Decimal("0"),
                output_field=DecimalField(max_digits=18, decimal_places=3),
            ),
        )
        for item in Item.objects.filter(is_active=True).select_related(
            "category"
        ):
            layer_val = StockCostLayer.objects.filter(
                item=item, quantity_remaining__gt=0
            ).aggregate(v=layer_value_expr)["v"]
            total_qty = StockBalance.objects.filter(item=item).aggregate(
                q=balance_qty_expr
            )["q"]
            if method == StockValuationMethod.LAST_PRICE:
                value = total_qty * (item.unit_price or Decimal("0"))
            else:
                value = layer_val
            if total_qty <= 0 and value <= 0:
                continue
            unit_cost = (
                (value / total_qty).quantize(Decimal("0.01"))
                if total_qty > 0
                else Decimal("0")
            )
            grand_total += value
            rows.append(
                {
                    "item_id": str(item.id),
                    "name": item.name,
                    "sku": item.sku,
                    "category_name": (
                        item.category.name if item.category_id else None
                    ),
                    "total_quantity": str(total_qty),
                    "unit_cost": str(unit_cost),
                    "value": str(value),
                }
            )
        return Response(
            {
                "method": method,
                "grand_total": str(grand_total),
                "items": rows,
            }
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="upload-image",
        parser_classes=[MultiPartParser],
    )
    def upload_image(self, request, pk=None):
        item = self.get_object()
        file = request.FILES.get("image")
        if not file:
            return Response(
                {"detail": "Aucun fichier fourni."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        item.image.save(file.name, file, save=True)
        item.image_url = request.build_absolute_uri(item.image.url)
        item.save(update_fields=["image_url", "updated_at"])
        return Response({"image_url": item.image_url})


class StockBalanceViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.StockBalanceAccess]
    queryset = StockBalance.objects.select_related(
        "item", "item__category", "item__unit", "storage_location"
    ).all()
    serializer_class = StockBalanceSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["item", "storage_location", "zone_label"]
    search_fields = ["item__name", "item__sku", "zone_label"]
    ordering_fields = ["quantity", "item__name", "updated_at"]
    ordering = ["item__name"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_authenticated:
            return qs.none()
        if getattr(u, "is_superuser", False) or rbac.is_admin(u):
            return qs
        r = rbac.get_user_role_code(u)
        if r == "magasinier":
            sids = user_scope.user_scoped_storage_location_ids(u)
            if sids is not None:
                return qs.filter(storage_location_id__in=sids)
            return qs.filter(storage_location__manager_user_id=u.id)
        if r == "chef_chantier":
            sids = user_scope.user_scoped_storage_location_ids(u)
            if sids is not None:
                return qs.filter(storage_location_id__in=sids)
        return qs


_DECIMAL_ZERO_EXPR = Value(
    Decimal("0"), output_field=DecimalField(max_digits=18, decimal_places=2)
)


def _resource_estimated_cost(resource: ProjectResource) -> Decimal:
    if resource.unit_cost is None:
        return Decimal("0")
    if (
        resource.cost_unit == ProjectResource.CostUnit.FORFAIT
        or not resource.planned_duration
    ):
        return resource.unit_cost
    return resource.unit_cost * resource.planned_duration


def _compute_project_costs(project: Project) -> dict:
    """Delegue au module partage project_costs."""
    return pcosts.compute_project_costs(project)


def _budget_vs_actual_by_category(project: Project) -> list[dict]:
    """
    Calcule budget vs réalisé par catégorie de coût (Section 7.3.7).

    Le réalisé `materiaux` est dérivé des sorties `completed` (non stocké).
    Les autres catégories utilisent `ProjectBudgetLine.actual_amount` si
    saisi, sinon 0. Retourne uniquement les catégories ayant un budget ou
    un réalisé non nul.
    """
    from collections import defaultdict

    Z = Decimal("0")

    materials_actual = (
        StockMovement.objects.filter(
            project=project,
            status=StockMovement.MovementStatus.COMPLETED,
            movement_type=StockMovement.MovementType.SORTIE,
        ).aggregate(t=Coalesce(Sum("total_cost"), _DECIMAL_ZERO_EXPR))["t"]
    )

    budget_by_cat = defaultdict(lambda: Z)
    actual_by_cat = defaultdict(lambda: Z)
    for line in ProjectBudgetLine.objects.filter(project=project):
        budget_by_cat[line.category] += line.budget_amount or Z
        if line.actual_amount is not None:
            actual_by_cat[line.category] += line.actual_amount
    # Le réalisé matériaux est dérivé des mouvements (override).
    actual_by_cat[ProjectBudgetLine.CostCategory.MATERIAUX] = materials_actual

    rows = []
    for cat, label in ProjectBudgetLine.CostCategory.choices:
        b = budget_by_cat.get(cat, Z)
        a = actual_by_cat.get(cat, Z)
        if b == Z and a == Z:
            continue
        variance = b - a
        variance_percent = (
            round(float(a) / float(b) * 100, 1) if b > 0 else None
        )
        rows.append(
            {
                "category": cat,
                "label": label,
                "budget": str(b),
                "actual": str(a),
                "variance": str(variance),
                "variance_percent": variance_percent,
                "over_budget": a > b,
                "auto_actual": cat
                == ProjectBudgetLine.CostCategory.MATERIAUX,
            }
        )
    return rows


class ProjectViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.AgencyProjectScopeAccess]
    queryset = (
        Project.objects.select_related("agency", "manager", "works_supervisor")
        .prefetch_related("phases", "budget_lines", "stock_movements")
        .all()
    )
    serializer_class = ProjectSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = [
        "status",
        "priority",
        "project_type",
        "agency",
        "manager",
        "works_supervisor",
        "is_draft",
        "criticality",
    ]
    search_fields = ["name", "reference", "client_name", "city", "description"]
    ordering_fields = [
        "name",
        "reference",
        "start_date",
        "end_date",
        "created_at",
        "budget_amount",
        "progress_percent",
    ]
    ordering = ["-created_at"]

    ALLOWED_TRANSITIONS = {
        "brouillon":     {"planification", "annule"},
        "planification": {"en_cours", "brouillon", "annule"},
        "en_cours":      {"suspendu", "termine"},
        "suspendu":      {"en_cours", "annule"},
        "termine":       set(),   # terminal
        "annule":        set(),   # terminal
    }

    def get_queryset(self):
        qs = super().get_queryset()
        return access.project_queryset_for_user(self.request.user, qs)

    def partial_update(self, request, *args, **kwargs):
        project = self.get_object()
        new_status = request.data.get("status")

        if new_status and new_status != project.status:
            allowed = self.ALLOWED_TRANSITIONS.get(project.status, set())
            if new_status not in allowed:
                return Response(
                    {
                        "status": (
                            f"Transition « {project.status} » → « {new_status} » non autorisée. "
                            f"Transitions valides : {sorted(allowed) or 'aucune (statut terminal)'}."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        return super().partial_update(request, *args, **kwargs)

    @action(detail=True, methods=["get"], url_path="cost-breakdown")
    def cost_breakdown(self, request, pk=None):
        """Détail complet du coût d'un chantier (Section 7.3.6)."""
        project = self.get_object()
        data = _compute_project_costs(project)
        data["by_category"] = _budget_vs_actual_by_category(project)
        return Response(data)

    @action(detail=True, methods=["get"], url_path="summary")
    def summary(self, request, pk=None):
        """KPIs agrégés pour l'en-tête du détail projet (Section 5.3.4)."""
        project = self.get_object()

        movements_qs = StockMovement.objects.filter(
            project=project,
            status=StockMovement.MovementStatus.COMPLETED,
        )

        total_movements = movements_qs.count()
        cost_materials = movements_qs.filter(
            movement_type=StockMovement.MovementType.SORTIE
        ).aggregate(
            total=Coalesce(
                Sum("total_cost"),
                Value(Decimal("0"), output_field=DecimalField(max_digits=18, decimal_places=2)),
            )
        )["total"]

        budget_lines = ProjectBudgetLine.objects.filter(project=project)
        budget_lines_total = budget_lines.aggregate(
            total=Coalesce(
                Sum("budget_amount"),
                Value(Decimal("0"), output_field=DecimalField(max_digits=18, decimal_places=2)),
            )
        )["total"]

        items_assigned = ItemProjectAssignment.objects.filter(
            project=project
        ).count()

        storage_locations_count = (
            StockMovement.objects.filter(project=project)
            .exclude(destination_storage_location=None)
            .values("destination_storage_location")
            .distinct()
            .count()
        )

        # Pour le ratio de consommation : on privilégie le budget global si présent,
        # sinon le total des lignes ventilées.
        reference_budget = project.budget_amount or budget_lines_total or Decimal("0")
        budget_consumed_percent = None
        if reference_budget and reference_budget > 0:
            budget_consumed_percent = round(
                float(cost_materials) / float(reference_budget) * 100, 1
            )

        costs = _compute_project_costs(project)

        return Response(
            {
                "project_id": str(project.id),
                "status": project.status,
                "progress_percent": project.progress_percent,
                "budget_amount": (
                    str(project.budget_amount) if project.budget_amount is not None else None
                ),
                "contract_value": (
                    str(project.contract_value)
                    if project.contract_value is not None
                    else None
                ),
                "currency": project.currency,
                "budget_lines_total": str(budget_lines_total),
                "cost_materials_consumed": str(cost_materials),
                "budget_consumed_percent": budget_consumed_percent,
                "total_movements": total_movements,
                "items_assigned": items_assigned,
                "storage_locations_count": storage_locations_count,
                "phases_count": project.phases.count(),
                # Section 7 — postes de coût consolidés.
                "cost_labour": costs["cost_labour"],
                "cost_subcontracting": costs["cost_subcontracting"],
                "cost_rental": costs["cost_rental"],
                "cost_losses": costs["cost_losses"],
                "cost_overhead": costs["cost_overhead"],
                "cost_total": costs["cost_total"],
                "margin": costs["margin"],
                "margin_percent": costs["margin_percent"],
            }
        )


class ProjectPhaseViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.AgencyProjectScopeAccess]
    queryset = ProjectPhase.objects.select_related("project").all()
    serializer_class = ProjectPhaseSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ["project", "status"]
    ordering_fields = ["order", "start_date", "end_date", "created_at"]
    ordering = ["project", "order"]

    def get_queryset(self):
        qs = super().get_queryset()
        pqs = access.project_queryset_for_user(
            self.request.user, Project.objects.all()
        )
        return qs.filter(project_id__in=pqs.values_list("id", flat=True))

    def perform_update(self, serializer):
        phase = serializer.save(updated_by=self.request.user)
        self._sync_project_progress(phase.project)

    def perform_create(self, serializer):
        phase = serializer.save(
            created_by=self.request.user,
            updated_by=self.request.user,
        )
        self._sync_project_progress(phase.project)

    def perform_destroy(self, instance):
        project = instance.project
        instance.delete()
        self._sync_project_progress(project)

    @staticmethod
    def _sync_project_progress(project):
        """Recalcule project.progress_percent = moyenne des phases."""
        phases = list(project.phases.values_list("progress_percent", flat=True))
        if not phases:
            return
        avg = round(sum(phases) / len(phases))
        Project.objects.filter(pk=project.pk).update(
            progress_percent=avg,
            updated_at=timezone.now(),
        )


class ProjectBudgetLineViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.AgencyProjectScopeAccess]
    queryset = ProjectBudgetLine.objects.select_related("project", "phase").all()
    serializer_class = ProjectBudgetLineSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ["project", "phase", "category"]
    ordering_fields = ["category", "budget_amount", "created_at"]
    ordering = ["project", "category", "label"]

    def get_queryset(self):
        qs = super().get_queryset()
        pqs = access.project_queryset_for_user(
            self.request.user, Project.objects.all()
        )
        return qs.filter(project_id__in=pqs.values_list("id", flat=True))


class ProjectResourceViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.AgencyProjectScopeAccess]
    queryset = ProjectResource.objects.select_related("project").all()
    serializer_class = ProjectResourceSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["project", "resource_kind"]
    search_fields = ["name", "status_label", "notes"]
    ordering_fields = ["resource_kind", "name", "availability_date"]
    ordering = ["resource_kind", "name"]

    def get_queryset(self):
        qs = super().get_queryset().select_related("project")
        pqs = access.project_queryset_for_user(
            self.request.user, Project.objects.all()
        )
        return qs.filter(project_id__in=pqs.values_list("id", flat=True))


class StockMovementViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.StockMovementAccess]
    parser_classes = [JSONParser, MultiPartParser]
    queryset = StockMovement.objects.select_related(
        "item",
        "source_storage_location",
        "destination_storage_location",
        "project",
        "approved_by",
    ).all()
    serializer_class = StockMovementSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = StockMovementFilter
    search_fields = [
        "reference_number",
        "item__name",
        "item__sku",
        "comment",
    ]
    ordering_fields = ["created_at", "quantity", "total_cost"]
    ordering = ["-created_at"]

    def perform_create(self, serializer):
        user = (
            self.request.user if self.request.user.is_authenticated else None
        )
        with transaction.atomic():
            movement = serializer.save(created_by=user, updated_by=user)
            movement.reference_number = _generate_movement_reference_number(
                movement
            )
            movement.save(
                update_fields=["reference_number", "updated_at"],
            )
            if movement.status == StockMovement.MovementStatus.COMPLETED:
                _apply_movement_to_balances(movement)

    @action(
        detail=True,
        methods=["post"],
        url_path="approve",
        permission_classes=[IsAuthenticated],
    )
    def approve(self, request, pk=None):
        movement = self.get_object()
        if not rbac.user_has_permission(request.user, "movement.validate"):
            return Response(
                {"detail": "Permission refusée."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if movement.status != StockMovement.MovementStatus.PENDING:
            return Response(
                {
                    "detail": (
                        f"Ce mouvement est en statut « {movement.status} » "
                        "et ne peut pas être approuvé."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        with transaction.atomic():
            _apply_movement_to_balances(movement)
            movement.status = StockMovement.MovementStatus.COMPLETED
            movement.approved_by = request.user
            movement.approved_at = timezone.now()
            movement.updated_by = request.user
            movement.save(
                update_fields=[
                    "status",
                    "approved_by",
                    "approved_at",
                    "updated_by",
                    "updated_at",
                ],
            )
        fresh = (
            StockMovement.objects.select_related(
                "item",
                "source_storage_location",
                "destination_storage_location",
                "project",
                "approved_by",
                "created_by",
            )
            .filter(pk=movement.pk)
            .first()
        )
        return Response(
            StockMovementSerializer(
                fresh,
                context={"request": request},
            ).data
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="reject",
        permission_classes=[IsAuthenticated],
    )
    def reject(self, request, pk=None):
        movement = self.get_object()
        if not rbac.user_has_permission(request.user, "movement.validate"):
            return Response(
                {"detail": "Permission refusée."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if movement.status != StockMovement.MovementStatus.PENDING:
            return Response(
                {
                    "detail": (
                        f"Ce mouvement est en statut « {movement.status} » "
                        "et ne peut pas être rejeté."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        reason = (request.data.get("rejection_reason") or "").strip()
        if not reason:
            return Response(
                {"detail": "Un motif de refus est requis."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        movement.status = StockMovement.MovementStatus.REJECTED
        movement.rejection_reason = reason
        movement.approved_by = request.user
        movement.approved_at = timezone.now()
        movement.updated_by = request.user
        movement.save(
            update_fields=[
                "status",
                "rejection_reason",
                "approved_by",
                "approved_at",
                "updated_by",
                "updated_at",
            ]
        )
        fresh = (
            StockMovement.objects.select_related(
                "item",
                "source_storage_location",
                "destination_storage_location",
                "project",
                "approved_by",
                "created_by",
            )
            .filter(pk=movement.pk)
            .first()
        )
        return Response(
            StockMovementSerializer(
                fresh,
                context={"request": request},
            ).data
        )

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if rbac.is_admin(u) or getattr(u, "is_superuser", False):
            return qs
        r = rbac.get_user_role_code(u)
        if r in (
            "comptable",
            "controleur_gestion",
            "conducteur_travaux",
            "responsable_achats",
        ):
            return qs
        if r == "chef_chantier":
            cids = user_scope.chef_chantier_project_ids(u)
            if cids is not None:
                return qs.filter(project_id__in=cids)
            return qs.filter(
                Q(project__manager_id=u.id)
                | Q(project__works_supervisor_id=u.id)
            )
        if r == "magasinier":
            sids = user_scope.user_scoped_storage_location_ids(u)
            if sids is not None:
                return qs.filter(
                    Q(source_storage_location_id__in=sids)
                    | Q(destination_storage_location_id__in=sids)
                )
            return qs.filter(
                Q(source_storage_location__manager_user_id=u.id)
                | Q(destination_storage_location__manager_user_id=u.id)
            )
        if r == "ouvrier_technicien":
            return qs.filter(created_by_id=u.id)
        return qs.none()


class ApprovalRuleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.RbacModelAdminAccess]
    queryset = ApprovalRule.objects.select_related(
        "approver_role", "project"
    ).all()
    serializer_class = ApprovalRuleSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = ApprovalRuleFilter
    ordering_fields = ["movement_type", "min_value_threshold", "created_at"]
    ordering = ["movement_type", "min_value_threshold"]


class ItemProjectAssignmentViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.AgencyProjectScopeAccess]
    queryset = ItemProjectAssignment.objects.select_related(
        "item", "project"
    ).all()
    serializer_class = ItemProjectAssignmentSerializer

    def get_queryset(self):
        qs = super().get_queryset().select_related("project")
        pqs = access.project_queryset_for_user(
            self.request.user, Project.objects.all()
        )
        return qs.filter(project_id__in=pqs.values_list("id", flat=True))


def _merge_smtp_form_overrides(instance: OrganizationSettings, data: dict) -> dict:
    """Merge JSON body with stored row (same rules as test-smtp / envoi réel)."""

    def _coerce_bool(value, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        s = str(value).strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off", ""):
            return False
        return default

    enabled = (
        _coerce_bool(data.get("smtp_enabled"), instance.smtp_enabled)
        if "smtp_enabled" in data
        else instance.smtp_enabled
    )
    host = (data.get("smtp_host") if "smtp_host" in data else instance.smtp_host) or ""
    host = (host or "").strip()
    if "smtp_port" in data and data.get("smtp_port") is not None:
        try:
            port = int(data["smtp_port"])
        except (TypeError, ValueError):
            port = int(instance.smtp_port or 587)
    else:
        port = int(instance.smtp_port or 587)
    use_ssl = (
        _coerce_bool(data.get("smtp_use_ssl"), bool(instance.smtp_use_ssl))
        if "smtp_use_ssl" in data
        else bool(instance.smtp_use_ssl)
    )
    use_tls_raw = (
        _coerce_bool(data.get("smtp_use_tls"), bool(instance.smtp_use_tls))
        if "smtp_use_tls" in data
        else bool(instance.smtp_use_tls)
    )
    use_tls = use_tls_raw and not use_ssl
    if "smtp_user" in data:
        user = str(data.get("smtp_user") or "").strip()
    else:
        user = (instance.smtp_user or "").strip() if instance.smtp_user is not None else ""
    if "smtp_password" in data:
        # Toujours prendre le corps du formulaire (y compris ""), sans retomber sur la base
        # quand l'utilisateur vide le champ (sinon un « faux » mot de passe serait contourné).
        _pw = data.get("smtp_password")
        password = "" if _pw is None else str(_pw)
    else:
        password = instance.smtp_password
    if "smtp_from_email" in data:
        from_email = (data.get("smtp_from_email") or "").strip()
    else:
        from_email = (instance.smtp_from_email or "").strip()
    return {
        "enabled": enabled,
        "host": host,
        "port": port,
        "use_ssl": use_ssl,
        "use_tls": use_tls,
        "user": user,
        "password": password,
        "from_email": from_email,
    }


def _smtp_test_pair_mismatch_response(p: dict) -> Response | None:
    """Gmail & co : la connexion TCP+STARTTLS peut réussir sans AUTH ; forcer le couple user+mot de passe pour un test fiable."""
    u = (p.get("user") or "").strip()
    pwc = "" if p.get("password") is None else str(p.get("password"))
    if u and not pwc.strip():
        return Response(
            {
                "detail": "Aucun mot de passe n’est utilisable pour l’authentification SMTP : le champ est vide et aucun "
                "mot de passe n’est enregistré pour cette intégration. Saisissez le mot de passe d’application ou "
                "enregistrez d’abord la configuration, ou laissez l’utilisateur vide pour un test de connectivité "
                "sans AUTH.",
                "success": False,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    if pwc.strip() and not u:
        return Response(
            {
                "detail": "Indiquez l’utilisateur SMTP en plus du mot de passe pour l’authentification.",
                "success": False,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


_AUTH_REDACT_RE = __import__("re").compile(
    r"(AUTH\s+\S+\s+)(\S+)", __import__("re").IGNORECASE
)


def _format_smtp_debug_line(args: tuple) -> str:
    """Normalize smtplib debug args → single line, redact AUTH credentials."""
    try:
        parts = [a if isinstance(a, str) else repr(a) for a in args]
        text = " ".join(parts)
    except Exception:  # noqa: BLE001
        text = repr(args)
    return _AUTH_REDACT_RE.sub(r"\1[redacted]", text)


def _build_smtp_test_message(from_email: str, to_email: str, host: str, port: int) -> str:
    """Build RFC 5322 multipart/alternative test message (text/plain + text/html)."""
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = "[Bâtir Pro] E-mail de test SMTP"
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(
        f"Test e-mail envoyé depuis Bâtir Pro via {host}:{port}."
    )
    msg.add_alternative(
        f"<p>Si vous recevez ce message, l’envoi avec les <strong>paramètres du formulaire</strong> "
        f"(hôte <code>{host}</code>, port {port}) fonctionne.</p>",
        subtype="html",
    )
    return msg.as_string()


def _run_smtp_debug_session(
    p: dict,
    *,
    raw_message_and_to: tuple[str, str, str] | None = None,
) -> dict:
    """
    Open a smtplib session with debuglevel=1 and capture the full protocol transcript
    (banner + EHLO/STARTTLS/AUTH + sendmail if `raw_message_and_to`).

    Bypasses Django's EmailBackend so we can:
    - set the debug hook BEFORE `connect()` and capture the server banner;
    - mask AUTH credentials from the transcript;
    - surface the actual smtplib exception when things fail mid-session.
    """
    import smtplib
    import ssl as ssl_module

    host = p["host"]
    port = int(p["port"])
    use_ssl = bool(p["use_ssl"])
    use_tls = bool(p["use_tls"]) and not use_ssl
    user = (p.get("user") or "").strip()
    pw_raw = p.get("password")
    pw = "" if pw_raw is None else str(pw_raw)

    log_lines: list[str] = [
        f"Connecting to {'smtps' if use_ssl else 'smtp'}://{host}:{port}/",
    ]

    def _capture(*args):
        log_lines.append(_format_smtp_debug_line(args))

    smtp = None
    error: str | None = None
    try:
        context = ssl_module.create_default_context()
        # Ne PAS passer host= dans __init__ : sinon smtplib connecte tout de suite et on
        # rate le banner (set_debuglevel interviendrait après). En revanche SMTP_SSL
        # wrap la socket avec server_hostname=self._host — qu’il faut donc forcer
        # manuellement, sans quoi Gmail (465) rejette le handshake TLS
        # (CertificateError / hostname mismatch / SNI vide).
        if use_ssl:
            smtp = smtplib.SMTP_SSL(context=context, timeout=20)
        else:
            smtp = smtplib.SMTP(timeout=20)
        smtp.set_debuglevel(1)
        smtp._print_debug = _capture  # type: ignore[assignment]
        smtp._host = host  # type: ignore[attr-defined] — requis pour SNI/cert SMTPS
        smtp.connect(host, port)
        smtp.ehlo()
        if use_tls:
            if not smtp.has_extn("starttls"):
                raise smtplib.SMTPNotSupportedError(
                    "Le serveur n’annonce pas STARTTLS sur cette session."
                )
            smtp.starttls(context=context)
            smtp.ehlo()
        if user and pw:
            smtp.login(user, pw)
        if raw_message_and_to is not None:
            from_addr, to_addr, msg_str = raw_message_and_to
            smtp.sendmail(from_addr, [to_addr], msg_str)
        try:
            smtp.quit()
        finally:
            smtp = None
    except Exception as exc:  # noqa: BLE001 — surfaced to the client, including the transcript
        error = f"{type(exc).__name__}: {exc!s}"
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass

    log_text = "\n".join(log_lines)
    if len(log_text) > 16000:
        log_text = log_text[:16000] + "\n… (tronqué)"
    return {
        "log": log_text,
        "error": error,
        "success": error is None,
    }


class OrganizationSettingsViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.SettingsIntegrationAccess]
    queryset = OrganizationSettings.objects.all()
    serializer_class = OrganizationSettingsSerializer

    @action(detail=True, methods=["post"], url_path="test-smtp")
    def test_smtp(self, request, pk=None):
        """
        Open a short SMTP connection to validate settings.
        JSON body (optional) can override the stored row to test the form without saving.
        """
        instance = self.get_object()
        data = request.data if isinstance(request.data, dict) else {}
        p = _merge_smtp_form_overrides(instance, data)
        if not p["enabled"] or not p["host"]:
            return Response(
                {
                    "detail": "Pour tester le SMTP : cochez l’activation et saisissez l’hôte "
                    "(les valeurs du formulaire sont prises en compte sans enregistrement).",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        pair_err = _smtp_test_pair_mismatch_response(p)
        if pair_err is not None:
            return pair_err
        u = (p.get("user") or "").strip()
        pwc = "" if p.get("password") is None else str(p.get("password"))

        result = _run_smtp_debug_session(p)
        if not result["success"]:
            err_text = f"Échec de la connexion : {result['error']}"
            hint = smtp_connection_test_hint(Exception(result["error"] or ""))
            return Response(
                {
                    "detail": f"{err_text} {hint}",
                    "success": False,
                    "debug_log": result["log"],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        mode = "SSL (SMTPS)" if p["use_ssl"] else "STARTTLS" if p["use_tls"] else "sans chiffrement"
        if u and pwc:
            auth_note = " Authentification SMTP (AUTH) vérifiée."
        elif not u and not pwc.strip():
            auth_note = (
                " Connexion TCP/TLS uniquement (pas d’AUTH) — "
                "pour vérifier un compte Gmail, renseignez utilisateur et mot de passe d’application."
            )
        else:
            auth_note = ""
        return Response(
            {
                "detail": f"Connexion réussie vers {p['host']}:{p['port']} en {mode}.{auth_note}",
                "success": True,
                "debug_log": result["log"],
            }
        )

    @action(detail=True, methods=["post"], url_path="send-test-smtp-email")
    def send_test_smtp_email(self, request, pk=None):
        """
        Envoie un e-mail HTML de test en utilisant les mêmes paramètres que le formulaire
        (sans enregistrement), pour valider l’envoi réel (connexion OK mais sendmail qui échoue).
        """
        instance = self.get_object()
        data = request.data if isinstance(request.data, dict) else {}
        p = _merge_smtp_form_overrides(instance, data)
        if not p["enabled"] or not p["host"]:
            return Response(
                {
                    "detail": "Activez le SMTP et renseignez l’hôte, ou utilisez les champs du formulaire.",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        pair_err = _smtp_test_pair_mismatch_response(p)
        if pair_err is not None:
            return pair_err
        to_email = (data.get("to_email") or "").strip() or (
            (getattr(request.user, "email", None) or "").strip()
        )
        if not to_email:
            return Response(
                {
                    "detail": "Indiquez un destinataire (to_email) ou utilisez un compte avec une adresse e-mail.",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        from_email = p["from_email"] or (getattr(settings, "DEFAULT_FROM_EMAIL", None) or "") or None
        if not from_email:
            return Response(
                {
                    "detail": "Renseignez l’adresse expéditeur (from) dans le formulaire ou enregistrez les paramètres.",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        msg_str = _build_smtp_test_message(from_email, to_email, p["host"], p["port"])
        result = _run_smtp_debug_session(
            p, raw_message_and_to=(from_email, to_email, msg_str)
        )
        if not result["success"]:
            err_text = f"Échec d’envoi : {result['error']}"
            hint = smtp_connection_test_hint(Exception(result["error"] or ""))
            return Response(
                {
                    "detail": f"{err_text} {hint}",
                    "success": False,
                    "debug_log": result["log"],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {
                "detail": f"E-mail de test envoyé à {to_email}.",
                "success": True,
                "debug_log": result["log"],
            }
        )


class IntegrationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.SettingsIntegrationAccess]
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer


class RoleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.RbacModelAdminAccess]
    queryset = Role.objects.all()
    serializer_class = RoleSerializer


class PermissionViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.RbacModelAdminAccess]
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer


class RolePermissionViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.RbacModelAdminAccess]
    queryset = RolePermission.objects.select_related("role", "permission").all()
    serializer_class = RolePermissionSerializer


class UserRoleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.RbacModelAdminAccess]
    queryset = UserRole.objects.select_related("user", "role").all()
    serializer_class = UserRoleSerializer


class ActivityEventViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.ActivityEventAccess]
    queryset = ActivityEvent.objects.select_related(
        "created_by", "updated_by"
    ).all()
    serializer_class = ActivityEventSerializer


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Alertes en lecture seule.
    Actions : read/, dismiss/, refresh/ (POST).
    """
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ["status", "severity", "alert_type", "project", "item"]
    ordering_fields = ["created_at", "severity"]
    ordering = ["-created_at"]

    def get_queryset(self):
        return Alert.objects.select_related(
            "item", "project", "stock_movement"
        ).filter(
            status__in=[Alert.Status.UNREAD, Alert.Status.READ]
        )

    @action(detail=False, methods=["get"], url_path="unread-count")
    def unread_count(self, request):
        count = Alert.objects.filter(status=Alert.Status.UNREAD).count()
        return Response({"count": count})

    @action(detail=True, methods=["post"], url_path="read")
    def mark_read(self, request, pk=None):
        alert = self.get_object()
        if alert.status == Alert.Status.UNREAD:
            alert.status = Alert.Status.READ
            alert.save(update_fields=["status", "updated_at"])
        return Response(AlertSerializer(alert).data)

    @action(detail=True, methods=["post"], url_path="dismiss")
    def dismiss(self, request, pk=None):
        alert = self.get_object()
        alert.status = Alert.Status.DISMISSED
        alert.save(update_fields=["status", "updated_at"])
        return Response(AlertSerializer(alert).data)

    @action(detail=False, methods=["post"], url_path="mark-all-read")
    def mark_all_read(self, request):
        updated = Alert.objects.filter(
            status=Alert.Status.UNREAD).update(status=Alert.Status.READ)
        return Response({"updated": updated})

    @action(detail=False, methods=["post"], url_path="refresh")
    def refresh(self, request):
        result = alert_engine.run_all()
        return Response(result)


def _set_refresh_cookie(response, refresh_value: str, *, persistent: bool) -> None:
    """
    Pose le cookie httpOnly portant le refresh token.

    `persistent=True` \u2192 cookie avec `Max-Age` = TTL du refresh (« rester connect\u00e9 »).
    `persistent=False` \u2192 cookie de session, supprim\u00e9 \u00e0 la fermeture du navigateur.
    """
    max_age = (
        int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())
        if persistent
        else None
    )
    response.set_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        refresh_value,
        max_age=max_age,
        httponly=True,
        secure=settings.JWT_REFRESH_COOKIE_SECURE,
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
        path=settings.JWT_REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response) -> None:
    response.delete_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        path=settings.JWT_REFRESH_COOKIE_PATH,
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_login(request):
    email = (request.data.get("email") or "").strip()
    password = request.data.get("password") or ""
    remember = bool(request.data.get("remember", True))
    if not email or not password:
        return Response(
            {"detail": "Veuillez saisir votre e-mail et votre mot de passe."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = User.objects.filter(email__iexact=email).first()
    if not user or not user.check_password(password):
        return Response(
            {"detail": "Adresse e-mail ou mot de passe incorrect."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not user.is_active:
        return Response(
            {"detail": "Ce compte est d\u00e9sactiv\u00e9. Contactez l'administrateur."},
            status=status.HTTP_403_FORBIDDEN,
        )

    refresh = RefreshToken.for_user(user)
    # Claim custom : la pr\u00e9f\u00e9rence « rester connect\u00e9 » survit aux rotations
    # (SimpleJWT pr\u00e9serve les claims utilisateur lors d'un refresh rotatif),
    # ce qui permet \u00e0 /auth/refresh/ de re-poser un cookie persistant ou non.
    refresh["rmb"] = 1 if remember else 0
    # Met \u00e0 jour `user.last_login` : ce endpoint contourne `django.contrib.auth.login()`
    # (pas de session JWT), donc Django ne le ferait pas tout seul et la colonne
    # « Derni\u00e8re connexion » dans /users resterait « Jamais ».
    update_last_login(None, user)

    response = Response({"access": str(refresh.access_token)})
    _set_refresh_cookie(response, str(refresh), persistent=remember)
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_refresh(request):
    """
    \u00c9met un nouvel access token \u00e0 partir du refresh transport\u00e9 par cookie httpOnly.
    Avec `ROTATE_REFRESH_TOKENS=True` + `BLACKLIST_AFTER_ROTATION=True`, l'ancien
    refresh est blacklist\u00e9 et un nouveau est r\u00e9-pos\u00e9 dans le cookie.
    """
    raw = request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
    if not raw:
        return Response(
            {"detail": "Session absente."},
            status=status.HTTP_401_UNAUTHORIZED,
        )
    serializer = TokenRefreshSerializer(data={"refresh": raw})
    try:
        serializer.is_valid(raise_exception=True)
    except (InvalidToken, TokenError):
        response = Response(
            {"detail": "Session expir\u00e9e."},
            status=status.HTTP_401_UNAUTHORIZED,
        )
        _clear_refresh_cookie(response)
        return response

    data = serializer.validated_data
    response = Response({"access": data["access"]})
    new_refresh_str = data.get("refresh")
    if new_refresh_str:
        # Lecture sans validation suppl\u00e9mentaire (le token vient d'\u00eatre \u00e9mis) ;
        # on r\u00e9cup\u00e8re le claim `rmb` pour reconduire la pr\u00e9f\u00e9rence « rester connect\u00e9 ».
        try:
            persistent = bool(RefreshToken(new_refresh_str).get("rmb", 1))
        except TokenError:
            persistent = True
        _set_refresh_cookie(response, new_refresh_str, persistent=persistent)
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_logout(request):
    """
    Blackliste le refresh courant (s'il est valide) et supprime le cookie.
    Renvoie 204 m\u00eame en l'absence de cookie/refresh, pour que le client
    puisse appeler /auth/logout/ de fa\u00e7on idempotente.
    """
    raw = request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
    if raw:
        try:
            RefreshToken(raw).blacklist()
        except TokenError:
            pass
    response = Response(status=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(response)
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_activate(request):
    """
    Active un compte créé par invitation : valide `UserProfile.invite_token`,
    définit le mot de passe, renseigne `activated_at` et invalide le jeton (usage unique).

    Distinct de `auth_password_reset_confirm` : ce dernier utilise
    `UserProfile.password_reset_token` pour les réinitialisations de mot de passe.
    """
    invite_token = (request.data.get("invite_token") or "").strip()
    new_password = request.data.get("new_password") or ""
    if not invite_token:
        return Response(
            {"detail": "Jeton d'invitation manquant."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if len(new_password) < 8:
        return Response(
            {"detail": "Le mot de passe doit contenir au moins 8 caractères."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    profile = (
        UserProfile.objects.select_related("user")
        .filter(invite_token=invite_token)
        .first()
    )
    if profile is None:
        return Response(
            {"detail": "Lien d'invitation invalide ou expiré."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if profile.activated_at is not None:
        return Response(
            {
                "detail": (
                    "Ce compte est déjà activé. Connectez-vous ou utilisez "
                    "« Mot de passe oublié » si vous avez oublié votre mot de passe."
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = profile.user
    if not user.is_active:
        return Response(
            {"detail": "Ce compte est désactivé. Contactez l'administrateur."},
            status=status.HTTP_403_FORBIDDEN,
        )
    with transaction.atomic():
        user.set_password(new_password)
        user.save(update_fields=["password"])
        profile.activated_at = timezone.now()
        profile.invite_token = ""
        profile.password_reset_token = ""
        profile.password_reset_sent_at = None
        profile.save(
            update_fields=[
                "activated_at",
                "invite_token",
                "password_reset_token",
                "password_reset_sent_at",
                "updated_at",
            ]
        )
    return Response(
        {"detail": "Votre compte est activé. Vous pouvez vous connecter."}
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_password_reset_request(request):
    email = (request.data.get("email") or "").strip()
    if not email:
        return Response(
            {"detail": "Veuillez saisir votre adresse e-mail."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = User.objects.filter(email__iexact=email).first()
    if user is not None and user.is_active:
        _issue_password_reset_for_user(user=user, request=request)
    return Response(
        {
            "detail": "Si un compte est associé à cette adresse, un message contenant la procédure de réinitialisation vous a été envoyé. Vérifiez vos courriers indésirables."
        }
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_password_reset_confirm(request):
    """
    Définit un nouveau mot de passe à partir du jeton `UserProfile.password_reset_token`
    (lien `?reset=` — distinct de l’activation d’invitation `?invite=`).
    """
    reset_token = (request.data.get("reset_token") or "").strip()
    new_password = request.data.get("new_password") or ""
    if not reset_token:
        return Response(
            {"detail": "Jeton de réinitialisation manquant."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if len(new_password) < 8:
        return Response(
            {"detail": "Le mot de passe doit contenir au moins 8 caractères."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    profile = (
        UserProfile.objects.select_related("user")
        .filter(password_reset_token=reset_token)
        .first()
    )
    if profile is None:
        return Response(
            {"detail": "Lien invalide ou expiré."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = profile.user
    if not user.is_active:
        return Response(
            {"detail": "Ce compte est désactivé. Contactez l'administrateur."},
            status=status.HTTP_403_FORBIDDEN,
        )
    sent_at = profile.password_reset_sent_at
    if sent_at is None:
        return Response(
            {"detail": "Lien invalide ou expiré."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    timeout_s = int(getattr(settings, "PASSWORD_RESET_TIMEOUT", 259200) or 259200)
    if timezone.now() - sent_at > timedelta(seconds=timeout_s):
        return Response(
            {"detail": "Lien invalide ou expiré."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    with transaction.atomic():
        user.set_password(new_password)
        user.save(update_fields=["password"])
        profile.password_reset_token = ""
        profile.password_reset_sent_at = None
        profile.save(
            update_fields=[
                "password_reset_token",
                "password_reset_sent_at",
                "updated_at",
            ]
        )
    send_password_reset_success_email(user=user, request=request)
    return Response(
        {
            "detail": "Votre mot de passe a été mis à jour. Vous pouvez vous connecter."
        }
    )


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def me(request):
    profile, _ = UserProfile.objects.select_related("user", "site").get_or_create(
        user=request.user,
    )
    if request.method == "GET":
        return Response(build_me_response(request.user, profile))
    ser = MeUpdateSerializer(
        data=request.data,
        partial=True,
        context={"request": request},
    )
    ser.is_valid(raise_exception=True)
    with transaction.atomic():
        ser.apply(request.user, profile)
    request.user.refresh_from_db()
    profile.refresh_from_db()
    return Response(build_me_response(request.user, profile))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def me_change_password(request):
    ser = ChangePasswordSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    old = ser.validated_data["old_password"]
    new = ser.validated_data["new_password"]
    if not request.user.check_password(old):
        return Response(
            {"detail": "Le mot de passe actuel est incorrect."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    request.user.set_password(new)
    request.user.save(update_fields=["password"])
    return Response(status=status.HTTP_204_NO_CONTENT)
