"""
Périmètre métier (chantiers / emplacements) : M2M sur `UserProfile`.

Si les listes sont **vides**, le repli est celui d’avant (ex. chef = manager du
`Project` ; magasinier = `StorageLocation.manager_user`). Dès qu’au moins un
id est enregistré, le filtrage API utilise exclusivement ce périmètre.
"""
from __future__ import annotations

import functools
from typing import Optional
from uuid import UUID

from django.apps import apps


@functools.lru_cache(maxsize=1)
def _user_profile_model():
    return apps.get_model("api", "UserProfile")


def get_profile_for_scope(user) -> Optional[object]:
    if not user or not user.is_authenticated:
        return None
    UserProfile = _user_profile_model()
    try:
        return UserProfile.objects.prefetch_related(
            "scoped_projects",
            "scoped_storage_locations",
        ).get(user_id=user.pk)
    except UserProfile.DoesNotExist:
        return None


def chef_chantier_project_ids(user) -> Optional[frozenset[UUID]]:
    """
    - None : aucune limite M2M → utiliser la règle legacy (manager / works_supervisor).
    - frozenset non vide : seuls ces projets.
    - frozenset() vide (profil sans chantiers assignés alors que le M2M est
      utilisé ailleurs) : pas de visibilité projet via M2M — laisser la couche
      appelante combiner ; pour requêtes on traite « comme aucun id ».
    """
    p = get_profile_for_scope(user)
    if p is None:
        return None
    qs = p.scoped_projects.values_list("id", flat=True)
    ids = list(qs)
    if not ids:
        return None
    return frozenset(ids)


def user_scoped_storage_location_ids(user) -> Optional[frozenset[UUID]]:
    """
    Périmètre dépôts / emplacements (ex. magasinier, stock chantier assuré
    côté emplacement).

    - None : repli rôle (ex. magasinier = `StorageLocation.manager_user`) ou
      pas de filtrage spécifique.
    - frozenset : emplacements explicitement assignés.
    """
    p = get_profile_for_scope(user)
    if p is None:
        return None
    qs = p.scoped_storage_locations.values_list("id", flat=True)
    ids = list(qs)
    if not ids:
        return None
    return frozenset(ids)
