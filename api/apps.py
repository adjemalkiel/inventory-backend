from __future__ import annotations

import logging
import os

from django.apps import AppConfig
from django.db.models.signals import post_migrate


logger = logging.getLogger(__name__)


# Valeurs par défaut pour le tout premier démarrage. Le mot de passe par défaut
# est volontairement trivial et logué ; il DOIT être changé dès la première
# connexion (bouton « Mot de passe oublié » ou page /reset-password avec un jeton valide).
_DEFAULT_SUPERUSER_EMAIL = "admin@batirpro.local"
_DEFAULT_SUPERUSER_PASSWORD = "ChangezMoi!2026"


def _ensure_default_superuser(sender, **kwargs) -> None:
    """
    Crée un superuser + `UserProfile` administrateur lors du premier `migrate`
    sur une base vide, pour permettre à l'admin de se connecter et d'inviter
    les autres utilisateurs via l'UI (`/users` → Inviter).

    - N'exécute rien si un superuser existe déjà.
    - Ne s'exécute qu'une fois (limité au signal `post_migrate` de l'app `api`,
      qui vient après la création des tables utilisateur de `auth`).
    - Identifiants lus depuis l'environnement :
        DJANGO_SUPERUSER_EMAIL      (défaut: admin@batirpro.local)
        DJANGO_SUPERUSER_USERNAME   (défaut: valeur de l'e-mail)
        DJANGO_SUPERUSER_PASSWORD   (défaut: ChangezMoi!2026 — À CHANGER)
        DJANGO_SUPERUSER_FIRST_NAME (optionnel)
        DJANGO_SUPERUSER_LAST_NAME  (optionnel)
    """
    # Garde-fou : ne pas écrire quand la migration porte sur une autre app
    # (le signal est branché sur `sender=config`, donc ce test est redondant
    # mais explicite la garantie).
    if getattr(sender, "label", None) != "api":
        return

    from django.contrib.auth import get_user_model

    from .models import Role, UserProfile, UserRole

    User = get_user_model()

    if User.objects.filter(is_superuser=True).exists():
        return

    email = (os.environ.get("DJANGO_SUPERUSER_EMAIL") or _DEFAULT_SUPERUSER_EMAIL).strip()
    username = (os.environ.get("DJANGO_SUPERUSER_USERNAME") or email).strip()
    password = os.environ.get("DJANGO_SUPERUSER_PASSWORD") or _DEFAULT_SUPERUSER_PASSWORD
    first_name = (os.environ.get("DJANGO_SUPERUSER_FIRST_NAME") or "Admin").strip()
    last_name = (os.environ.get("DJANGO_SUPERUSER_LAST_NAME") or "").strip()

    # Si un compte non-admin avec cet e-mail/nom existe déjà (ex. création
    # manuelle avant migrations), on le promeut plutôt que de dupliquer.
    user = (
        User.objects.filter(email__iexact=email).first()
        or User.objects.filter(username__iexact=username).first()
    )
    created = False
    if user is None:
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        created = True
    else:
        changed = False
        if not user.is_superuser or not user.is_staff:
            user.is_superuser = True
            user.is_staff = True
            changed = True
        if not user.has_usable_password():
            user.set_password(password)
            changed = True
        if changed:
            user.save()

    UserProfile.objects.get_or_create(
        user=user,
        defaults={"job_title": "Administrateur"},
    )

    # Affecte le rôle RBAC `administrateur` au superuser bootstrap. Le seed
    # `0008_seed_rbac_catalog` a normalement déjà créé la ligne `Role` ; on
    # tolère son absence (tests, base partielle) en sortant silencieusement.
    admin_role = Role.objects.filter(code="administrateur").first()
    if admin_role is not None:
        UserRole.objects.get_or_create(
            user=user,
            defaults={"role": admin_role},
        )

    using_defaults = (
        email == _DEFAULT_SUPERUSER_EMAIL
        and password == _DEFAULT_SUPERUSER_PASSWORD
    )
    banner = "créé" if created else "promu superutilisateur"
    logger.warning(
        "[bootstrap] Superutilisateur %s : %s (username=%s).",
        banner, email, username,
    )
    if using_defaults:
        # Message très visible : identifiants par défaut, à changer.
        logger.warning(
            "[bootstrap] Identifiants par DÉFAUT utilisés — connectez-vous sur "
            "/login avec e-mail=%s et mot de passe=%s, puis changez-le "
            "IMMÉDIATEMENT via « Mot de passe oublié » ou en définissant un nouveau mot de passe sur /reset-password. "
            "Pour un autre couple d'identifiants, définissez les variables "
            "d'environnement DJANGO_SUPERUSER_EMAIL et DJANGO_SUPERUSER_PASSWORD "
            "avant le premier `migrate`.",
            email, password,
        )


class ApiConfig(AppConfig):
    name = "api"

    def ready(self) -> None:
        # Branche le bootstrap sur `post_migrate` uniquement pour cette app
        # (évite d'exécuter le hook pour les migrations de `auth`, `contenttypes`,
        # etc. qui sont lancées dans le même `migrate`).
        post_migrate.connect(_ensure_default_superuser, sender=self)
