from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.contrib.auth.tokens import default_token_generator
import secrets

from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.conf import settings
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
                phone=(d.get("phone") or "").strip()[:64],
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
        permission_classes=[IsAuthenticated],
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
        permission_classes=[IsAuthenticated],
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
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        sent, delivery = send_password_reset_email(
            user=user, request=request, uidb64=uid, token=token
        )
        return Response(
            {
                "user": UserSerializer(user).data,
                "password_reset_email_sent": bool(sent),
                "email_delivery": delivery,
            }
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
    # Met à jour `user.last_login` : ce endpoint contourne `django.contrib.auth.login()`
    # (pas de session côté API token), donc Django ne le ferait pas tout seul et
    # la colonne « Dernière connexion » dans /users resterait « Jamais ».
    update_last_login(None, user)
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
