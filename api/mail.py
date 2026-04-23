"""E-mail helpers (password reset, etc.)."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from django.conf import settings
from django.core.mail import EmailMessage, get_connection
from django.template.loader import render_to_string
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_org_email_connection_and_from() -> tuple[object | None, str | None]:
    """
    If organization SMTP is enabled and a host is set, return (connection, from_email);
    else (None, None) so send_mail() uses Django project defaults (EMAIL_* / .env).

    Settings must match what Paramètres → Intégrations → SMTP saves
    (OrganizationSettings: smtp_enabled, smtp_host, port, tls/ssl, user, password, from).
    """
    from .models import OrganizationSettings

    org = OrganizationSettings.objects.first()
    if not org or not org.smtp_enabled or not (org.smtp_host or "").strip():
        return None, None
    use_ssl = bool(org.smtp_use_ssl)
    use_tls = bool(org.smtp_use_tls) and not use_ssl
    conn = get_connection(
        host=org.smtp_host.strip(),
        port=int(org.smtp_port or 587),
        username=org.smtp_user or None,
        password=org.smtp_password or None,
        use_tls=use_tls,
        use_ssl=use_ssl,
    )
    from_email = (org.smtp_from_email or "").strip() or None
    return conn, from_email


def send_mail_via_org_settings(
    *,
    subject: str,
    html_body: str,
    recipient_list: list[str],
) -> int:
    """
    Send a **single-part HTML** e-mail (no text/plain) using org SMTP when configured,
    else global Django settings.

    Use this for all application e-mail so the same connection and From address apply
    as in the SMTP settings UI (after Enregistrer).
    """
    conn, org_from = get_org_email_connection_and_from()
    from_email = org_from or settings.DEFAULT_FROM_EMAIL
    msg = EmailMessage(
        subject=subject,
        body=html_body,
        from_email=from_email,
        to=recipient_list,
        connection=conn,
    )
    msg.content_subtype = "html"
    return msg.send(fail_silently=False)


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
) -> bool:
    """
    HTML e-mail: invitation to join, role/site summary, and link to set password
    (same token mechanism as password reset → /reset-password).
    """
    from django.contrib.auth.tokens import default_token_generator
    from django.utils.encoding import force_bytes
    from django.utils.http import urlsafe_base64_encode

    user = profile.user
    to_email = (getattr(user, "email", None) or "").strip()
    if not to_email:
        logger.warning("Invitation : utilisateur id=%s sans e-mail, envoi ignoré.", user.pk)
        return False

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
        n = send_mail_via_org_settings(
            subject=INVITATION_SUBJECT,
            html_body=body_html,
            recipient_list=[to_email],
        )
        if n > 0:
            logger.info("Invitation envoyée à %s", to_email)
        return n > 0
    except Exception:
        logger.exception("Échec d'envoi de l’e-mail d’invitation pour %s", to_email)
        return False


def send_password_reset_email(
    *,
    user,
    request,
    uidb64: str,
    token: str,
) -> bool:
    """
    Send password reset e-mail (HTML only, `password_reset_fr.html`).
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
        n = send_mail_via_org_settings(
            subject=PASSWORD_RESET_REQUEST_SUBJECT,
            html_body=body_html,
            recipient_list=[user.email],
        )
        return n > 0
    except Exception:
        logger.exception(
            "Échec d'envoi de l'e-mail de réinitialisation pour %s",
            user.email,
        )
        return False


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
) -> bool:
    """
    Notify a user (HTML) that their org profile / access rights were updated
    (user-profiles create or update with `notify_user: true` from the app).
    """
    user = profile.user
    to_email = (getattr(user, "email", None) or "").strip()
    if not to_email:
        logger.warning(
            "Notification accès : l’utilisateur id=%s n’a pas d’adresse e-mail, envoi ignoré.",
            user.pk,
        )
        return False

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
        n = send_mail_via_org_settings(
            subject=ACCESS_UPDATE_SUBJECT,
            html_body=body_html,
            recipient_list=[to_email],
        )
        ok = n > 0
        if ok:
            logger.info(
                "Notification accès : message accepté par le backend e-mail pour %s "
                "(si EMAIL_BACKEND=console, le contenu est dans le terminal du serveur, pas une vraie livraison).",
                to_email,
            )
        return ok
    except Exception:
        logger.exception(
            "Échec d'envoi de l'e-mail de notification d'accès pour %s", to_email
        )
        return False


def send_password_reset_success_email(*, user, request) -> bool:
    """
    Notify the user that their password was changed (after reset link flow).
    HTML body follows the Bâtir Pro card layout (see password_reset_success_fr.html).
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
        n = send_mail_via_org_settings(
            subject=subject,
            html_body=body_html,
            recipient_list=[user.email],
        )
        return n > 0
    except Exception:
        logger.exception(
            "Échec d'envoi de l'e-mail de confirmation de changement de mot de passe pour %s",
            user.email,
        )
        return False
