"""E-mail helpers (password reset, etc.)."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from django.conf import settings
from django.core.mail import EmailMessage, get_connection
from django.template.loader import render_to_string
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_org_email_connection_and_from() -> tuple[object | None, str | None, bool]:
    """
    If organization SMTP is enabled and a host is set, return a tuple
    `(connection, from_email, used_org_smtp=True)`. Otherwise, return
    `(None, None, False)` so the caller falls back to Django's project
    default `EMAIL_BACKEND` (which, without `EMAIL_HOST`, is
    `console.EmailBackend` in dev → mails are only printed to stdout,
    **not** really sent).

    Settings must match what Paramètres → Intégrations → SMTP saves
    (OrganizationSettings: smtp_enabled, smtp_host, port, tls/ssl, user, password, from).

    We also pin `backend=django.core.mail.backends.smtp.EmailBackend` so
    the org SMTP parameters are actually honored even when the project
    defaults to the console backend in dev.
    """
    from .models import OrganizationSettings

    org = OrganizationSettings.objects.first()
    if not org or not org.smtp_enabled or not (org.smtp_host or "").strip():
        return None, None, False
    use_ssl = bool(org.smtp_use_ssl)
    use_tls = bool(org.smtp_use_tls) and not use_ssl
    # Force the real SMTP backend : sinon `get_connection()` utilise
    # `settings.EMAIL_BACKEND` (console en dev) et ignore silencieusement
    # host/port/user/password → les messages sont juste imprimés.
    conn = get_connection(
        backend="django.core.mail.backends.smtp.EmailBackend",
        host=org.smtp_host.strip(),
        port=int(org.smtp_port or 587),
        username=(org.smtp_user or "").strip(),
        password=org.smtp_password or "",
        use_tls=use_tls,
        use_ssl=use_ssl,
    )
    from_email = (org.smtp_from_email or "").strip() or None
    return conn, from_email, True


# Possible string values for `delivery_kind`, returned by every helper below.
# The frontend uses them to show the right message and let admins know
# when a "success" was actually just printed to the Django console.
DELIVERY_ORG_SMTP = "org-smtp"
DELIVERY_CONSOLE = "console"
DELIVERY_DJANGO_SMTP = "django-smtp"
DELIVERY_LOCMEM = "locmem"
DELIVERY_FILEBASED = "filebased"
DELIVERY_DUMMY = "dummy"
DELIVERY_OTHER = "other"


def _delivery_kind(used_org: bool) -> str:
    """Map current email backend to a stable identifier for API/UI consumers."""
    if used_org:
        return DELIVERY_ORG_SMTP
    backend = (getattr(settings, "EMAIL_BACKEND", "") or "").lower()
    if "console" in backend:
        return DELIVERY_CONSOLE
    if "locmem" in backend:
        return DELIVERY_LOCMEM
    if "filebased" in backend:
        return DELIVERY_FILEBASED
    if "dummy" in backend:
        return DELIVERY_DUMMY
    if "smtp" in backend:
        return DELIVERY_DJANGO_SMTP
    return DELIVERY_OTHER


_REAL_SMTP_DELIVERY_KINDS = frozenset({DELIVERY_ORG_SMTP, DELIVERY_DJANGO_SMTP})


def send_mail_via_org_settings(
    *,
    subject: str,
    html_body: str,
    recipient_list: list[str],
) -> tuple[int, str]:
    """
    Send a **single-part HTML** e-mail (no text/plain) via a real SMTP server.

    Resolution order (the first configured path wins):
    1. `OrganizationSettings` row with `smtp_enabled=True` and `smtp_host` set
       (Paramètres → Intégrations → SMTP). Connection is pinned to
       `django.core.mail.backends.smtp.EmailBackend` so host/port/user/password
       are actually honored.
    2. `settings.EMAIL_BACKEND == "django.core.mail.backends.smtp.EmailBackend"`
       (project defaults populated from `EMAIL_HOST`, `EMAIL_HOST_USER`, …).

    **Refuses to send via non-SMTP backends** (`console`, `locmem`, `filebased`,
    `dummy`, custom). In dev without SMTP, `console.EmailBackend` would only
    print the MIME message to stdout and return `1`, which used to mask
    non-deliveries as successes — that blind spot is now closed and logged.

    Returns `(sent_count, delivery_kind)`. `delivery_kind ∈ {"org-smtp",
    "django-smtp", "console", "locmem", "filebased", "dummy", "other"}`.
    Callers should treat `delivery_kind` outside of {"org-smtp",
    "django-smtp"} as a non-delivery.
    """
    conn, org_from, used_org = get_org_email_connection_and_from()
    kind = _delivery_kind(used_org)

    if kind not in _REAL_SMTP_DELIVERY_KINDS:
        # Aucun backend SMTP réel : on refuse d'envoyer pour ne pas « mentir »
        # avec `sent_count=1` sur un message simplement imprimé dans la console
        # (cas par défaut en dev quand OrganizationSettings.smtp_enabled=False
        # et qu'aucune variable EMAIL_HOST n'est définie).
        logger.error(
            "Envoi e-mail « %s » annulé : aucun SMTP configuré (backend effectif "
            "« %s »). Activez Paramètres → Intégrations → SMTP et cliquez sur "
            "Enregistrer, ou définissez les variables EMAIL_HOST / EMAIL_HOST_USER "
            "/ EMAIL_HOST_PASSWORD dans l'environnement Django.",
            subject,
            kind,
        )
        return 0, kind

    from_email = org_from or settings.DEFAULT_FROM_EMAIL
    msg = EmailMessage(
        subject=subject,
        body=html_body,
        from_email=from_email,
        to=recipient_list,
        connection=conn,
    )
    msg.content_subtype = "html"
    n = msg.send(fail_silently=False)
    return n, kind


def smtp_connection_test_hint(exc: BaseException) -> str:
    """Short French hint for common SMTP connectivity / auth failures (test only)."""
    msg = str(exc)
    low = msg.lower()
    if "gaierror" in type(exc).__name__.lower() or "getaddrinfo" in low or "name or service not known" in low:
        return (
            "Indice : nom d’hôte introuvable (faute de frappe ou DNS). "
            "Vérifiez « smtp.… » auprès de votre fournisseur de messagerie."
        )
    if "refused" in low or "connection refused" in low or "errno 10061" in low:
        return (
            "Indice : connexion refusée sur ce port — souvent mauvais port (587 vs 465) "
            "ou mauvais mode (STARTTLS vs SSL). Vérifiez aussi un pare-feu local / réseau."
        )
    if "timed out" in low or "timeout" in low:
        return (
            "Indice : délai dépassé — hôte injoignable, port bloqué, ou filtrage réseau / pare-feu."
        )
    if "ssl" in low or "tls" in low or "certificate" in low or "wrong version" in low:
        return (
            "Indice : problème TLS/SSL — essayez l’autre mode (STARTTLS sur 587 ou SSL sur 465) "
            "selon la doc de votre fournisseur."
        )
    if (
        "535" in msg
        or "authentication" in low
        or (
            "auth" in low
            and ("failed" in low or "invalid" in low or "denied" in low)
        )
    ):
        return (
            "Indice : le serveur refuse l’identification — vérifiez l’utilisateur, le mot de passe "
            "ou l’usage d’un « mot de passe d’application » si la boîte impose 2FA."
        )
    return (
        "Indice : contrôlez l’hôte, le port, le chiffrement (STARTTLS / SSL) et les identifiants."
    )


PASSWORD_RESET_REQUEST_SUBJECT = "Réinitialisation de votre mot de passe Bâtir Pro"
INVITATION_SUBJECT = "Vous êtes invité sur Bâtir Pro"


def send_user_invitation_email(
    *,
    profile,
    request,
) -> tuple[bool, str]:
    """
    HTML e-mail: invitation to join, role/site summary, and link to set password
    (same token mechanism as password reset → /reset-password).

    Returns `(sent, delivery_kind)` so the admin UI can distinguish a real
    SMTP delivery from a console/dummy fallback.
    """
    from django.contrib.auth.tokens import default_token_generator
    from django.utils.encoding import force_bytes
    from django.utils.http import urlsafe_base64_encode

    user = profile.user
    to_email = (getattr(user, "email", None) or "").strip()
    if not to_email:
        logger.warning("Invitation : utilisateur id=%s sans e-mail, envoi ignoré.", user.pk)
        return False, "no-recipient"

    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    q = urlencode(
        {
            "uid": uidb64,
            "token": token,
            "email": user.email,
        }
    )
    set_password_url = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/reset-password?{q}"

    prenom = (getattr(user, "first_name", None) or "").strip() or "Bonjour"
    role_label = (
        profile.get_role_display() if hasattr(profile, "get_role_display") else str(profile.role)
    )
    if profile.site_id and getattr(profile, "site", None):
        site_name = profile.site.name
    else:
        site_name = "Tous les sites"
    job_title = (getattr(profile, "job_title", None) or "").strip() or "—"

    ctx = {
        "prenom": prenom,
        "email": user.email,
        "role_label": role_label,
        "site_name": site_name,
        "job_title": job_title,
        "lien_mot_de_passe": set_password_url,
        "equipe_assistance_email": settings.BATIRPRO_SUPPORT_EMAIL,
    }
    body_html = render_to_string("email/invitation_fr.html", ctx)

    try:
        n, kind = send_mail_via_org_settings(
            subject=INVITATION_SUBJECT,
            html_body=body_html,
            recipient_list=[to_email],
        )
        if n > 0:
            logger.info("Invitation envoyée à %s via %s", to_email, kind)
        return n > 0, kind
    except Exception:
        logger.exception("Échec d'envoi de l’e-mail d’invitation pour %s", to_email)
        return False, "error"


def send_password_reset_email(
    *,
    user,
    request,
    uidb64: str,
    token: str,
) -> tuple[bool, str]:
    """
    Send password reset e-mail (HTML only, `password_reset_fr.html`).

    Returns `(sent, delivery_kind)` so callers can flag console-backend
    « deliveries » (dev) vs real SMTP.
    """
    q = urlencode(
        {
            "uid": uidb64,
            "token": token,
            "email": user.email,
        }
    )
    reset_url = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/reset-password?{q}"

    prenom = (getattr(user, "first_name", None) or "").strip() or "Utilisateur"
    timeout_s = int(getattr(settings, "PASSWORD_RESET_TIMEOUT", 259200) or 259200)
    days = max(1, timeout_s // 86400)
    duree_validite = f"{days} jours" if days != 1 else "24 heures"

    now = timezone.localtime(timezone.now())
    date_heure_demande = now.strftime("%d/%m/%Y %H:%M")
    appareil = (
        (request.META.get("HTTP_USER_AGENT") or "")[:250] or "Non spécifié"
    )
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        ip_approx = xff.split(",")[0].strip()
    else:
        ip_approx = request.META.get("REMOTE_ADDR") or "Inconnue"

    ctx = {
        "prenom": prenom,
        "email": user.email,
        "lien_reinitialisation": reset_url,
        "duree_validite": duree_validite,
        "date_heure_demande": date_heure_demande,
        "appareil": appareil,
        "ip_approx": ip_approx,
        "equipe_assistance_email": settings.BATIRPRO_SUPPORT_EMAIL,
        "url_assistance": settings.BATIRPRO_ASSISTANCE_URL,
        "url_confidentialite": settings.BATIRPRO_PRIVACY_URL,
    }

    body_html = render_to_string("email/password_reset_fr.html", ctx)

    try:
        n, kind = send_mail_via_org_settings(
            subject=PASSWORD_RESET_REQUEST_SUBJECT,
            html_body=body_html,
            recipient_list=[user.email],
        )
        return n > 0, kind
    except Exception:
        logger.exception(
            "Échec d'envoi de l'e-mail de réinitialisation pour %s",
            user.email,
        )
        return False, "error"


ACCESS_UPDATE_SUBJECT = "Mise à jour de vos accès — Bâtir Pro"


def _editor_display_name(request) -> str:
    if not request:
        return "un administrateur"
    u = getattr(request, "user", None)
    if not u or not u.is_authenticated:
        return "un administrateur"
    name = (u.get_full_name() or "").strip()
    if name:
        return name
    return (getattr(u, "username", None) or getattr(u, "email", None) or "Administrateur")[:200]


def send_access_update_notification_email(
    *, profile, request=None
) -> tuple[bool, str]:
    """
    Notify a user (HTML) that their org profile / access rights were updated
    (user-profiles create or update with `notify_user: true` from the app).

    Returns `(sent, delivery_kind)` so console-backend fallbacks are surfaced.
    """
    user = profile.user
    to_email = (getattr(user, "email", None) or "").strip()
    if not to_email:
        logger.warning(
            "Notification accès : l’utilisateur id=%s n’a pas d’adresse e-mail, envoi ignoré.",
            user.pk,
        )
        return False, "no-recipient"

    logger.info(
        "Notification accès : envoi HTML à %s (profil %s).",
        to_email,
        getattr(profile, "pk", profile),
    )

    prenom = (getattr(user, "first_name", None) or "").strip() or "Utilisateur"
    role_label = profile.get_role_display() if hasattr(profile, "get_role_display") else str(
        profile.role
    )
    job_title = (getattr(profile, "job_title", None) or "").strip() or "—"
    if profile.site_id and getattr(profile, "site", None):
        site_label = profile.site.name
    else:
        site_label = "Tous les sites"
    now = timezone.localtime(timezone.now())
    date_heure = now.strftime("%d/%m/%Y %H:%M")
    app_url = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/"

    ctx = {
        "prenom": prenom,
        "compte_email": user.email,
        "role_label": role_label,
        "job_title": job_title,
        "site_label": site_label,
        "date_heure": date_heure,
        "modifie_par": _editor_display_name(request),
        "app_url": app_url,
        "support_email": settings.BATIRPRO_SUPPORT_EMAIL,
    }
    body_html = render_to_string("email/access_update_notification_fr.html", ctx)

    try:
        n, kind = send_mail_via_org_settings(
            subject=ACCESS_UPDATE_SUBJECT,
            html_body=body_html,
            recipient_list=[to_email],
        )
        ok = n > 0
        if ok:
            logger.info(
                "Notification accès : message accepté par le backend e-mail pour %s via %s.",
                to_email,
                kind,
            )
        return ok, kind
    except Exception:
        logger.exception(
            "Échec d'envoi de l'e-mail de notification d'accès pour %s", to_email
        )
        return False, "error"


def send_password_reset_success_email(*, user, request) -> tuple[bool, str]:
    """
    Notify the user that their password was changed (after reset link flow).
    HTML body follows the Bâtir Pro card layout (see password_reset_success_fr.html).

    Returns `(sent, delivery_kind)` so console-backend fallbacks are surfaced.
    """
    prenom = (getattr(user, "first_name", None) or "").strip() or "Utilisateur"
    now = timezone.localtime(timezone.now())
    date_heure = now.strftime("%d/%m/%Y %H:%M")
    appareil = (request.META.get("HTTP_USER_AGENT") or "")[:250] or "Non spécifié"
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        ip_approx = xff.split(",")[0].strip()
    else:
        ip_approx = request.META.get("REMOTE_ADDR") or "Inconnue"

    login_url = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/login"
    ctx = {
        "prenom": prenom,
        "email": user.email,
        "login_url": login_url,
        "date_heure": date_heure,
        "ip_approx": ip_approx,
        "appareil": appareil,
        "equipe_assistance_email": settings.BATIRPRO_SUPPORT_EMAIL,
        "url_assistance": settings.BATIRPRO_ASSISTANCE_URL,
        "url_confidentialite": settings.BATIRPRO_PRIVACY_URL,
    }

    subject = "Votre mot de passe Bâtir Pro a été modifié"
    body_html = render_to_string("email/password_reset_success_fr.html", ctx)

    try:
        n, kind = send_mail_via_org_settings(
            subject=subject,
            html_body=body_html,
            recipient_list=[user.email],
        )
        return n > 0, kind
    except Exception:
        logger.exception(
            "Échec d'envoi de l'e-mail de confirmation de changement de mot de passe pour %s",
            user.email,
        )
        return False, "error"
