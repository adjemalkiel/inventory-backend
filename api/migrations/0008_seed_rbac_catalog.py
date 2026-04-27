"""
Data migration : peuple le catalogue RBAC.

1. Crée les 21 `Permission` du catalogue (`api.rbac.PERMISSION_DEFINITIONS`).
2. Crée les 8 `Role` métier (`api.rbac.ROLE_DEFINITIONS`) avec leur `code` /
   `name` / `description`.
3. Lie `RolePermission` selon la matrice rôle → permissions.
4. Pour chaque `UserProfile` existant, crée la ligne `UserRole`
   correspondante en mappant l'ancien slug `UserProfile.role` :

       administrateur  -> administrateur
       magasinier      -> magasinier
       chef_chantier   -> chef_chantier
       consultant      -> controleur_gestion   (lecture rapports analytiques)

   Le mapping `consultant` est documenté ici car les 4 anciennes valeurs
   ne couvrent pas toutes les 8 nouvelles : `consultant` est l'analogue
   le plus proche du `Contrôleur de gestion` (lecture seule rapports).
"""

from django.db import migrations
from django.utils import timezone


# Mapping legacy `UserProfile.role` (TextChoices à 4 valeurs) → nouveau slug.
LEGACY_ROLE_TO_CODE: dict[str, str] = {
    "administrateur": "administrateur",
    "magasinier": "magasinier",
    "chef_chantier": "chef_chantier",
    "consultant": "controleur_gestion",
}


def seed_rbac_catalog(apps, schema_editor):
    # Imports tardifs pour fonctionner avec `apps.get_model` (historical models).
    from api.rbac import PERMISSION_DEFINITIONS, ROLE_DEFINITIONS

    Permission = apps.get_model("api", "Permission")
    Role = apps.get_model("api", "Role")
    RolePermission = apps.get_model("api", "RolePermission")
    UserProfile = apps.get_model("api", "UserProfile")
    UserRole = apps.get_model("api", "UserRole")

    now = timezone.now()

    # 1. Permissions
    permission_by_code: dict[str, object] = {}
    for code, description in PERMISSION_DEFINITIONS:
        perm, _ = Permission.objects.update_or_create(
            code=code,
            defaults={
                "description": description,
                "updated_at": now,
            },
        )
        permission_by_code[code] = perm

    # 2. Rôles + 3. Liaisons RolePermission
    role_by_code: dict[str, object] = {}
    all_perm_codes = [code for code, _ in PERMISSION_DEFINITIONS]

    for definition in ROLE_DEFINITIONS:
        code = str(definition["code"])
        name = str(definition["name"])
        description = str(definition["description"])

        # `Role.name` est `unique=True` → on cherche par `code` puis par `name`
        # pour rester idempotent (re-run safe).
        role = Role.objects.filter(code=code).first() or Role.objects.filter(name=name).first()
        if role is None:
            role = Role.objects.create(
                code=code,
                name=name,
                description=description,
                created_at=now,
                updated_at=now,
            )
        else:
            role.code = code
            role.name = name
            role.description = description
            role.updated_at = now
            role.save(update_fields=["code", "name", "description", "updated_at"])
        role_by_code[code] = role

        # Permissions liées (`"*"` = catalogue complet pour `administrateur`).
        perm_codes = (
            all_perm_codes
            if definition["permissions"] == "*"
            else list(definition["permissions"])  # type: ignore[arg-type]
        )

        # Reset propre : on supprime les liens absents puis on (re)crée les liens manquants.
        existing_links = {
            (rp.role_id, rp.permission_id): rp
            for rp in RolePermission.objects.filter(role=role)
        }
        wanted_perm_ids = {permission_by_code[c].pk for c in perm_codes}
        for (role_id, perm_id), rp in existing_links.items():
            if perm_id not in wanted_perm_ids:
                rp.delete()
        for c in perm_codes:
            perm = permission_by_code[c]
            RolePermission.objects.get_or_create(
                role=role,
                permission=perm,
                defaults={"created_at": now, "updated_at": now},
            )

    # 4. Affecte un UserRole à chaque profil existant à partir de l'ancien slug.
    for profile in UserProfile.objects.all():
        legacy_value = (getattr(profile, "role", "") or "").strip()
        new_code = LEGACY_ROLE_TO_CODE.get(legacy_value, "magasinier")
        role = role_by_code.get(new_code)
        if role is None:
            continue
        UserRole.objects.update_or_create(
            user=profile.user,
            defaults={
                "role": role,
                "updated_at": now,
            },
        )


def unseed_rbac_catalog(apps, schema_editor):
    """Reverse : on conserve les données (pas de suppression destructive)."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0007_rbac_schema"),
    ]

    operations = [
        migrations.RunPython(seed_rbac_catalog, unseed_rbac_catalog),
    ]
