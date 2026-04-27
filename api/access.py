"""
Matrice d'accès par rôle (ViewSets DRF) — source métier : conventions produit
(`users.view`, `users.manage`, `articles.manage`, `inventory.view`, etc.).

Les superutilisateurs Django contournent les garde-fous (tout autorisé).
"""
from __future__ import annotations

from django.db.models import Q, QuerySet
from rest_framework.permissions import (
    BasePermission,
    SAFE_METHODS,
)

from . import rbac
from . import scope as user_scope

# ---------------------------------------------------------------------------
# Aides
# ---------------------------------------------------------------------------


def _super_or_admin(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    if getattr(user, "is_superuser", False):
        return True
    return rbac.is_admin(user)


def _view_inventory(user) -> bool:
    return rbac.user_has_permission(
        user, "inventory.view"
    ) or rbac.user_has_permission(user, "inventory.view.global")


def _role(user) -> str | None:
    return rbac.get_user_role_code(user)


# Rôles explicitement **sans** accès lecture Projets/Agences/liaisons
_RO_BLOCK_PROJECT_READ = frozenset(
    {
        "magasinier",
        "ouvrier_technicien",
        "responsable_achats",
    }
)

# Rôles avec lecture seule (liste / fiche) sur la « famille » projets
_RO_PROJECT_READ = frozenset(
    {
        "administrateur",
        "conducteur_travaux",
        "comptable",
        "chef_chantier",
        "controleur_gestion",
    }
)

_RO_PROJECT_WRITE = frozenset(
    {
        "administrateur",
        "conducteur_travaux",
    }
)


# ---------------------------------------------------------------------------
# Utilisateurs & profils
# ---------------------------------------------------------------------------


class UsersOrProfilesAccess(BasePermission):
    """
    Users/Profiles: CRUD admin ; lecture conducteur (users.view) ; refus ailleurs.
    Les actions explicites `invite/`, `resend-invitation/`, `send-password-reset/`
    restent protégées par `IsAdminRole` au niveau @action.
    """

    message = "Droits insuffisants sur les comptes utilisateur."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        if request.method in SAFE_METHODS and rbac.user_has_permission(
            u, "users.view"
        ):
            return True
        return rbac.user_has_permission(u, "users.manage")


# ---------------------------------------------------------------------------
# Rôles & métadonnées RBAC (tableaux Role, Permission, RolePermission, UserRole)
# ---------------------------------------------------------------------------


class RbacModelAdminAccess(BasePermission):
    """Rôles / permissions / affectations: réservé administrateur (rôle + super)."""

    message = "Réservé aux administrateurs."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        return _super_or_admin(u)


# ---------------------------------------------------------------------------
# Catalogue (articles, catégories, unités)
# ---------------------------------------------------------------------------


class ItemCatalogAccess(BasePermission):
    """
    Lectures: tout rôle avec vue stock.
    Écriture: `articles.manage` (ex. responsable achats) ou admin.
    """

    message = "Droits insuffisants sur le catalogue articles."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        if request.method in SAFE_METHODS:
            return _view_inventory(u)
        return rbac.user_has_permission(u, "articles.manage")


# ---------------------------------------------------------------------------
# Sites (sites dépôts)
# ---------------------------------------------------------------------------


class SiteViewSetAccess(BasePermission):
    """Admin: CRUD ; autres rôles: lecture seule (liste des sites)."""

    message = "Droits insuffisants sur les sites."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        if request.method in SAFE_METHODS:
            return _role(u) is not None
        return False


# ---------------------------------------------------------------------------
# Agences, projets, ressources projet, affectations article↔projet
# ---------------------------------------------------------------------------


class AgencyProjectScopeAccess(BasePermission):
    """
    - Lecture: admin, conducteur, comptable, chef de chantier, contrôleur (pas
      magasinier / ouvrier / responsable achats, cf. matrice).
    - Écriture: admin, conducteur de travaux.
    """

    message = "Droits insuffisants sur le périmètre projets / agences."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        r = _role(u)
        if r is None:
            return False
        if r in _RO_BLOCK_PROJECT_READ:
            return False
        if request.method in SAFE_METHODS:
            return r in _RO_PROJECT_READ
        return r in _RO_PROJECT_WRITE

    def has_object_permission(
        self, request, view, obj
    ) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        r = _role(u)
        if r in _RO_BLOCK_PROJECT_READ:
            return False
        if r in _RO_PROJECT_WRITE and request.method not in SAFE_METHODS:
            return True
        if request.method in SAFE_METHODS and r in _RO_PROJECT_READ:
            if r == "chef_chantier":
                from .models import Agency, ItemProjectAssignment, Project, ProjectResource

                if isinstance(obj, Agency):
                    cids = user_scope.chef_chantier_project_ids(u)
                    if cids is not None:
                        return Project.objects.filter(agency=obj, id__in=cids).exists()
                    return (
                        Project.objects.filter(agency=obj)
                        .filter(
                            Q(manager_id=u.id) | Q(works_supervisor_id=u.id)
                        )
                        .exists()
                    )
                p = _project_from_obj(obj)
                if p is not None:
                    cids = user_scope.chef_chantier_project_ids(u)
                    if cids is not None:
                        return p.id in cids
                    return p.manager_id == u.id or p.works_supervisor_id == u.id
                return True
            return True
        if request.method not in SAFE_METHODS:
            return False
        return r in _RO_PROJECT_READ


def _project_from_obj(obj):
    """Extrait un `Project` d'un objet (Project, ProjectResource, ItemProjectAssignment, …)."""
    from .models import ItemProjectAssignment, Project, ProjectResource

    if isinstance(obj, Project):
        return obj
    if isinstance(obj, (ProjectResource, ItemProjectAssignment)):
        return obj.project
    return None


def project_queryset_for_user(user, base: QuerySet) -> QuerySet:
    """Filtre les projets visibles (chef: assignation M2M ou manager/superviseur)."""
    if not user.is_authenticated:
        return base.none()
    if _super_or_admin(user) or _role(user) in (
        "conducteur_travaux",
        "comptable",
        "controleur_gestion",
    ):
        return base
    if _role(user) == "chef_chantier":
        cids = user_scope.chef_chantier_project_ids(user)
        if cids is not None:
            return base.filter(id__in=cids)
        return base.filter(
            Q(manager_id=user.id) | Q(works_supervisor_id=user.id)
        )
    if _role(user) in _RO_BLOCK_PROJECT_READ:
        return base.none()
    return base.none()


# ---------------------------------------------------------------------------
# Emplacements de stockage
# ---------------------------------------------------------------------------


class StorageLocationAccess(BasePermission):
    """
    Comptable / ouvrier / responsable achats: pas d'accès (matrice : « - »).
    Autres: lecture ; écriture: admin seul.
    """

    message = "Droits insuffisants sur les emplacements de stockage."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        r = _role(u)
        if r in (
            "comptable",
            "ouvrier_technicien",
            "responsable_achats",
        ):
            return False
        if request.method in SAFE_METHODS:
            return r is not None and _view_inventory(u)
        return False

    def has_object_permission(
        self, request, view, obj
    ) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        r = _role(u)
        if r in (
            "comptable",
            "ouvrier_technicien",
            "responsable_achats",
        ):
            return False
        if request.method in SAFE_METHODS and _view_inventory(u):
            if r == "magasinier":
                sids = user_scope.user_scoped_storage_location_ids(u)
                if sids is not None:
                    return obj.id in sids
                return obj.manager_user_id == u.id
            return True
        if request.method not in SAFE_METHODS and _super_or_admin(u):
            return True
        return False


# ---------------------------------------------------------------------------
# Soldes de stock
# ---------------------------------------------------------------------------


class StockBalanceAccess(BasePermission):
    """Lecture: tout rôle avec vue stock ; écriture: admin (sinon ajustement via mouvements)."""

    message = "Droits insuffisants sur les soldes de stock."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        if request.method in SAFE_METHODS:
            return _view_inventory(u)
        return False


# ---------------------------------------------------------------------------
# Mouvements
# ---------------------------------------------------------------------------


class StockMovementAccess(BasePermission):
    """
    Matrice StockMovements (CRUD, lecture, validation, périmètre dépôt/chantier,
    « demande » pour ouvrier).
    """

    message = "Droits insuffisants sur les mouvements de stock."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        m = request.method
        r = _role(u)
        if r is None:
            return False
        if m in SAFE_METHODS:
            return _can_read_movements(u, r)
        if m == "POST":
            if r in (
                "conducteur_travaux",
                "comptable",
                "controleur_gestion",
                "responsable_achats",
            ):
                return False
            if r == "chef_chantier":
                return rbac.user_has_permission(
                    u, "movement.create.own_project"
                )
            if r == "magasinier":
                return rbac.user_has_permission(
                    u, "movement.create.own_site"
                )
            if r == "ouvrier_technicien":
                return rbac.user_has_permission(u, "materials.request")
            return False
        if m in ("PUT", "PATCH", "DELETE"):
            if r == "comptable" or r in (
                "controleur_gestion",
                "responsable_achats",
            ):
                return False
            if r == "conducteur_travaux":
                return rbac.user_has_permission(u, "movement.validate")
            if r == "ouvrier_technicien":
                return True
            if r in ("chef_chantier", "magasinier"):
                return True
        return False

    def has_object_permission(
        self, request, view, obj
    ) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        m = request.method
        r = _role(u)
        if m in SAFE_METHODS:
            if not _can_read_movements(u, r):
                return False
            if r == "magasinier":
                return _movement_touches_user_depot(u, obj)
            if r == "chef_chantier":
                return _movement_on_user_project(u, obj)
            if r == "ouvrier_technicien":
                return obj.created_by_id == u.id
            return r in (
                "comptable",
                "controleur_gestion",
                "conducteur_travaux",
                "responsable_achats",
            ) or _view_inventory(u)
        if m in ("PUT", "PATCH", "DELETE"):
            if r == "ouvrier_technicien":
                return obj.created_by_id == u.id
            if r == "conducteur_travaux":
                return rbac.user_has_permission(u, "movement.validate")
            if r == "magasinier":
                return _movement_touches_user_depot(
                    u, obj
                ) and rbac.user_has_permission(
                    u, "movement.create.own_site"
                )
            if r == "chef_chantier":
                return _movement_on_user_project(
                    u, obj
                ) and rbac.user_has_permission(
                    u, "movement.create.own_project"
                )
        return False


def _can_read_movements(user, r: str) -> bool:
    if r in (
        "comptable",
        "controleur_gestion",
        "responsable_achats",
    ):
        return rbac.user_has_permission(
            user, "inventory.view"
        ) or rbac.user_has_permission(user, "inventory.view.global")
    if r in (
        "chef_chantier",
        "magasinier",
        "ouvrier_technicien",
        "conducteur_travaux",
    ):
        return _view_inventory(user) or r == "conducteur_travaux"
    if r in ("administrateur",):
        return True
    return _view_inventory(user)


def _movement_touches_user_depot(user, obj) -> bool:
    uid = user.id
    s = obj.source_storage_location
    d = obj.destination_storage_location
    sids = user_scope.user_scoped_storage_location_ids(user)
    for loc in (s, d):
        if loc is None:
            continue
        if sids is not None:
            if loc.id in sids:
                return True
        elif loc.manager_user_id == uid:
            return True
    return False


def _movement_on_user_project(user, obj) -> bool:
    p = obj.project
    if p is None:
        return False
    cids = user_scope.chef_chantier_project_ids(user)
    if cids is not None:
        return p.id in cids
    return p.manager_id == user.id or p.works_supervisor_id == user.id


# ---------------------------------------------------------------------------
# Paramètres / intégrations
# ---------------------------------------------------------------------------


class SettingsIntegrationAccess(BasePermission):
    message = "Réservé aux administrateurs (paramétrage)."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        return rbac.user_has_permission(u, "settings.manage")


# ---------------------------------------------------------------------------
# Journal d'activité
# ---------------------------------------------------------------------------


class ActivityEventAccess(BasePermission):
    """Lecture: tout utilisateur authentifié; écriture: admin (audit)."""

    message = "Droits insuffisants sur l'historique d'activité."

    def has_permission(self, request, view) -> bool:
        u = request.user
        if not u.is_authenticated:
            return False
        if _super_or_admin(u):
            return True
        if request.method in SAFE_METHODS:
            return True
        return False
