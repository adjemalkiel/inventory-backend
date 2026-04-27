"""
Classes de permission DRF adoss\u00e9es au syst\u00e8me RBAC (`api.rbac`).

Pour l'instant on ne d\u00e9ploie pas une grille fine permission-par-endpoint :
on se contente d'un garde « administrateur uniquement » sur les actions
sensibles d\u00e9clench\u00e9es depuis la page Utilisateurs (invitation, renvoi
d'invitation, reset de mot de passe).

Les checks fins par `Permission.code` viendront avec la mise sous garde
des autres viewsets (\u00e9tape ult\u00e9rieure du plan).
"""
from rest_framework.permissions import BasePermission

from . import rbac


class IsAdminRole(BasePermission):
    """
    Autorise un user qui est superuser Django **ou** qui a le r\u00f4le RBAC
    `administrateur` (cf. `rbac.is_admin`). Refuse tout le reste, y compris
    les utilisateurs anonymes.
    """

    message = (
        "R\u00e9serv\u00e9 aux administrateurs : votre r\u00f4le ne dispose pas de cette action."
    )

    def has_permission(self, request, view) -> bool:
        return rbac.is_admin(getattr(request, "user", None))
