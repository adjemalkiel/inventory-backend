"""
Catalogue RBAC : définit les 8 rôles métier et la matrice rôle → permissions.

C'est la **source de vérité** consommée par :
- la migration de seed (`0008_seed_rbac_catalog`) ;
- les serializers (`InviteUserSerializer.role` choices) ;
- les helpers (`get_user_role_code`, `get_user_role_label`).

Ne change **jamais** un `code` existant sans data-migration : c'est le slug
stable côté API/frontend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser


# ---------------------------------------------------------------------------
# Permissions (catalogue plat : un permission code = une capacité)
# ---------------------------------------------------------------------------

PERMISSION_DEFINITIONS: list[tuple[str, str]] = [
    # Inventaire / stock
    ("inventory.view", "Consulter le stock (périmètre du rôle)."),
    ("inventory.view.global", "Lecture globale du stock, tous sites/chantiers confondus."),
    ("inventory.physical_count", "Réaliser un inventaire physique (comptage)."),
    # Mouvements de stock
    ("movement.create", "Enregistrer un mouvement (toutes localisations)."),
    ("movement.create.own_site", "Enregistrer un mouvement sur son dépôt de rattachement."),
    ("movement.create.own_project", "Enregistrer un mouvement sur son chantier de rattachement."),
    ("movement.validate", "Valider / contre-signer un mouvement."),
    ("movement.receive", "Réceptionner une livraison fournisseur."),
    # Gestion administrative
    ("articles.manage", "Gérer le catalogue des articles."),
    ("suppliers.manage", "Gérer les fournisseurs."),
    ("purchase_prices.manage", "Gérer les prix d'achat."),
    ("orders.manage", "Gérer les commandes / bons de commande."),
    # Demandes (terrain)
    ("replenishment.request", "Émettre une demande de réapprovisionnement."),
    ("materials.request", "Émettre une demande de matériel (mobile)."),
    ("losses.report", "Signaler une perte / casse."),
    # Rapports
    ("reports.financial", "Accéder aux rapports financiers."),
    ("reports.cost", "Accéder aux rapports de coûts et marges."),
    ("reports.budget", "Comparer budget prévisionnel vs réalisé."),
    ("reports.site", "Accéder aux rapports chantier."),
    # Administration de la plateforme
    ("users.view", "Consulter la liste des comptes et des profils (lecture seule)."),
    ("users.manage", "Gérer les comptes et invitations utilisateur."),
    ("settings.manage", "Configurer la plateforme (paramètres, intégrations)."),
]


# ---------------------------------------------------------------------------
# Rôles et matrice rôle → permission codes
# ---------------------------------------------------------------------------

ROLE_DEFINITIONS: list[dict[str, object]] = [
    {
        "code": "administrateur",
        "name": "Administrateur",
        "description": (
            "Directeur / Gérant / Admin système. Accès total : configuration, "
            "utilisateurs, rapports financiers."
        ),
        # Accès total => toutes les permissions du catalogue.
        "permissions": "*",
    },
    {
        "code": "conducteur_travaux",
        "name": "Conducteur de travaux",
        "description": (
            "Superviseur opérationnel multi-chantiers. Lecture globale, "
            "validation des mouvements, rapports chantier."
        ),
        "permissions": [
            "users.view",
            "inventory.view",
            "inventory.view.global",
            "movement.validate",
            "reports.site",
        ],
    },
    {
        "code": "chef_chantier",
        "name": "Chef de chantier",
        "description": (
            "Responsable d'un chantier spécifique. CRUD des mouvements sur son "
            "chantier, consultation du stock, demandes de réapprovisionnement."
        ),
        "permissions": [
            "inventory.view",
            "movement.create.own_project",
            "replenishment.request",
        ],
    },
    {
        "code": "magasinier",
        "name": "Magasinier",
        "description": (
            "Gestionnaire de dépôt. CRUD des mouvements sur son dépôt, "
            "réception des livraisons, inventaires physiques."
        ),
        "permissions": [
            "inventory.view",
            "movement.create.own_site",
            "movement.receive",
            "inventory.physical_count",
        ],
    },
    {
        "code": "responsable_achats",
        "name": "Responsable achats",
        "description": (
            "Approvisionnement et fournisseurs. Gestion des articles, "
            "fournisseurs, prix d'achat, commandes."
        ),
        "permissions": [
            "inventory.view",
            "articles.manage",
            "suppliers.manage",
            "purchase_prices.manage",
            "orders.manage",
        ],
    },
    {
        "code": "comptable",
        "name": "Comptable",
        "description": (
            "Responsable financier. Lecture seule sur stocks et mouvements. "
            "Accès aux rapports financiers et de coûts."
        ),
        "permissions": [
            "inventory.view.global",
            "reports.financial",
            "reports.cost",
        ],
    },
    {
        "code": "controleur_gestion",
        "name": "Contrôleur de gestion",
        "description": (
            "Analyse budgétaire. Lecture des rapports coûts, comparaison "
            "budget/réalisé, marges."
        ),
        "permissions": [
            "inventory.view.global",
            "reports.cost",
            "reports.budget",
        ],
    },
    {
        "code": "ouvrier_technicien",
        "name": "Ouvrier / Technicien",
        "description": (
            "Utilisateur terrain. Consultation du stock, signalement des "
            "pertes/casses, demandes de matériel (mobile)."
        ),
        "permissions": [
            "inventory.view",
            "losses.report",
            "materials.request",
        ],
    },
]


def get_role_codes() -> list[str]:
    """Liste ordonnée des slugs de rôles (utilisée par les `ChoiceField`)."""
    return [r["code"] for r in ROLE_DEFINITIONS]  # type: ignore[misc]


def get_role_choices() -> list[tuple[str, str]]:
    """Couples `(code, name)` consommés par DRF `ChoiceField.choices`."""
    return [(r["code"], r["name"]) for r in ROLE_DEFINITIONS]  # type: ignore[misc]


# Cache simple : code → label humain.
ROLE_LABELS: dict[str, str] = {
    str(r["code"]): str(r["name"]) for r in ROLE_DEFINITIONS
}


# ---------------------------------------------------------------------------
# Helpers d'accès (non-cassants si l'utilisateur n'a pas encore de rôle)
# ---------------------------------------------------------------------------

def get_user_role_code(user: "AbstractBaseUser | None") -> Optional[str]:
    """Retourne le slug du rôle de `user` (ou `None` si non affecté)."""
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    user_role = (
        user.user_roles  # type: ignore[attr-defined]
        .select_related("role")
        .first()
    )
    if user_role is None or user_role.role is None:
        return None
    return user_role.role.code or None


def get_user_role_label(user: "AbstractBaseUser | None") -> Optional[str]:
    """Retourne le libellé humain du rôle de `user` (ou `None`)."""
    code = get_user_role_code(user)
    if code is None:
        return None
    return ROLE_LABELS.get(code, code)


# ---------------------------------------------------------------------------
# Constantes & helpers d'autorisation
# ---------------------------------------------------------------------------

ADMIN_ROLE_CODE = "administrateur"


def is_admin(user: "AbstractBaseUser | None") -> bool:
    """
    Vrai si `user` peut effectuer des actions d'administration : superuser
    Django (filet de sécurité pour le bootstrap) ou rôle RBAC `administrateur`.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superuser", False):
        return True
    return get_user_role_code(user) == ADMIN_ROLE_CODE


def get_user_permissions(user: "AbstractBaseUser | None") -> list[str]:
    """
    Liste des codes de permission accordés à `user` via son rôle RBAC.

    - Superuser ou rôle `administrateur` → catalogue complet (`*`).
    - Autre rôle → lecture de la table `RolePermission` (matrice seedée).
    - Sans rôle ou anonyme → `[]`.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return []
    if getattr(user, "is_superuser", False):
        return [code for code, _ in PERMISSION_DEFINITIONS]

    code = get_user_role_code(user)
    if code is None:
        return []
    if code == ADMIN_ROLE_CODE:
        return [code for code, _ in PERMISSION_DEFINITIONS]

    # Import local pour éviter un cycle (rbac.py est importé par models.py
    # via les serializers / la migration de seed).
    from .models import RolePermission

    return list(
        RolePermission.objects
        .filter(role__code=code)
        .order_by("permission__code")
        .values_list("permission__code", flat=True)
    )


def user_has_permission(
    user: "AbstractBaseUser | None", permission_code: str
) -> bool:
    """Vrai si `permission_code` est accordé (via rôle, ou admin/super)."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    return permission_code in get_user_permissions(user)
