from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
import secrets

from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import get_connection
from rest_framework import status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import (
    ActivityEvent,
    Agency,
    Category,
    Integration,
    Item,
    ItemProjectAssignment,
    OrganizationSettings,
    Permission,
    Project,
    ProjectResource,
    Role,
    RolePermission,
    Site,
    StockBalance,
    StockMovement,
    StorageLocation,
    UnitOfMeasure,
    UserProfile,
    UserRole,
)
from .mail import (
    send_password_reset_email,
    send_password_reset_success_email,
    send_user_invitation_email,
    smtp_connection_test_hint,
)
from .serializers import (
    ActivityEventSerializer,
    AgencySerializer,
    CategorySerializer,
    ChangePasswordSerializer,
    IntegrationSerializer,
    InviteUserSerializer,
    ItemProjectAssignmentSerializer,
    ItemSerializer,
    MeUpdateSerializer,
    OrganizationSettingsSerializer,
    PermissionSerializer,
    ProjectResourceSerializer,
    ProjectSerializer,
    RolePermissionSerializer,
    RoleSerializer,
    SiteSerializer,
    StockBalanceSerializer,
    StockMovementSerializer,
    StorageLocationSerializer,
    UnitOfMeasureSerializer,
    UserProfileSerializer,
    UserRoleSerializer,
    UserSerializer,
    build_me_response,
)

User = get_user_model()


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
    queryset = Site.objects.all()
    serializer_class = SiteSerializer


class UserViewSet(viewsets.ModelViewSet):
    """
    CRUD for Django's built-in User (no custom user model in api.models).
    """

    queryset = User.objects.all().order_by("username")
    serializer_class = UserSerializer

    @action(
        detail=False,
        methods=["post"],
        url_path="invite",
        permission_classes=[IsAuthenticated],
    )
    def invite(self, request):
        """
        Créer un utilisateur inactif côté mot de passe, son profil, et envoyer
        l’e-mail d’invitation (lien pour définir le mot de passe, comme reset).
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
                role=d["role"],
                job_title=(d.get("job_title") or "").strip()[:255],
                site=site,
                invite_token=secrets.token_urlsafe(48),
                invited_at=timezone.now(),
                created_by=request.user,
                updated_by=request.user,
            )

        fresh = (
            UserProfile.objects.select_related("user", "site")
            .filter(pk=prof.pk)
            .first()
        )
        sent = send_user_invitation_email(profile=fresh, request=request)
        return Response(
            {
                "user": UserSerializer(user).data,
                "profile": UserProfileSerializer(fresh).data,
                "invitation_email_sent": sent,
            },
            status=status.HTTP_201_CREATED,
        )


class AgencyViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Agency.objects.all()
    serializer_class = AgencySerializer


class StorageLocationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = StorageLocation.objects.all()
    serializer_class = StorageLocationSerializer


class UnitOfMeasureViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = UnitOfMeasure.objects.all()
    serializer_class = UnitOfMeasureSerializer


class CategoryViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class UserProfileViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = UserProfile.objects.select_related("user", "site").all()
    serializer_class = UserProfileSerializer


class ItemViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Item.objects.select_related("category", "unit").all()
    serializer_class = ItemSerializer


class StockBalanceViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = StockBalance.objects.select_related(
        "item", "storage_location"
    ).all()
    serializer_class = StockBalanceSerializer


class ProjectViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Project.objects.select_related(
        "agency", "manager", "works_supervisor"
    ).all()
    serializer_class = ProjectSerializer


class ProjectResourceViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = ProjectResource.objects.select_related("project").all()
    serializer_class = ProjectResourceSerializer


class StockMovementViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = StockMovement.objects.select_related(
        "item",
        "source_storage_location",
        "destination_storage_location",
        "project",
    ).all()
    serializer_class = StockMovementSerializer


class ItemProjectAssignmentViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = ItemProjectAssignment.objects.select_related(
        "item", "project"
    ).all()
    serializer_class = ItemProjectAssignmentSerializer


class OrganizationSettingsViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
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
        user = (data.get("smtp_user") if "smtp_user" in data else instance.smtp_user) or ""
        if "smtp_password" in data and (data.get("smtp_password") or ""):
            password = data.get("smtp_password")
        else:
            password = instance.smtp_password
        if not enabled or not host:
            return Response(
                {
                    "detail": "Pour tester le SMTP : cochez l’activation et saisissez l’hôte "
                    "(les valeurs du formulaire sont prises en compte sans enregistrement).",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        conn = None
        try:
            conn = get_connection(
                host=host,
                port=port,
                username=user or None,
                password=password or None,
                use_tls=use_tls,
                use_ssl=use_ssl,
            )
            conn.open()
        except Exception as exc:  # noqa: BLE001 — surface connectivity errors to the client
            err_text = f"Échec de la connexion : {exc!s}"
            hint = smtp_connection_test_hint(exc)
            return Response(
                {
                    "detail": f"{err_text} {hint}",
                    "success": False,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        mode = "SSL (SMTPS)" if use_ssl else "STARTTLS" if use_tls else "sans chiffrement"
        return Response(
            {
                "detail": f"Connexion réussie vers {host}:{port} en {mode}.",
                "success": True,
            }
        )


class IntegrationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer


class RoleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer


class PermissionViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer


class RolePermissionViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = RolePermission.objects.select_related("role", "permission").all()
    serializer_class = RolePermissionSerializer


class UserRoleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = UserRole.objects.select_related("user", "role").all()
    serializer_class = UserRoleSerializer


class ActivityEventViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = ActivityEvent.objects.select_related(
        "created_by", "updated_by"
    ).all()
    serializer_class = ActivityEventSerializer


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_login(request):
    email = (request.data.get("email") or "").strip()
    password = request.data.get("password") or ""
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
            {"detail": "Ce compte est désactivé. Contactez l'administrateur."},
            status=status.HTTP_403_FORBIDDEN,
        )
    token, _ = Token.objects.get_or_create(user=user)
    return Response(
        {
            "token": token.key,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def auth_logout(request):
    Token.objects.filter(user=request.user).delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


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
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        send_password_reset_email(user=user, request=request, uidb64=uid, token=token)
    return Response(
        {
            "detail": "Si un compte est associé à cette adresse, un message contenant la procédure de réinitialisation vous a été envoyé. Vérifiez vos courriers indésirables."
        }
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_password_reset_confirm(request):
    uidb64 = (request.data.get("uid") or "").strip()
    token = (request.data.get("token") or "").strip()
    new_password = request.data.get("new_password") or ""
    if not uidb64 or not token:
        return Response(
            {"detail": "Lien de réinitialisation invalide."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if len(new_password) < 8:
        return Response(
            {"detail": "Le mot de passe doit contenir au moins 8 caractères."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        raw = urlsafe_base64_decode(uidb64)
        pk = int(raw.decode())
        user = User.objects.get(pk=pk)
    except (ValueError, TypeError, OverflowError, UnicodeDecodeError, User.DoesNotExist):
        return Response(
            {"detail": "Lien invalide ou expiré."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not default_token_generator.check_token(user, token):
        return Response(
            {"detail": "Lien invalide ou expiré."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user.set_password(new_password)
    user.save(update_fields=["password"])
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
        defaults={"role": UserProfile.Role.MAGASINIER},
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
