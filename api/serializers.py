from django.contrib.auth import get_user_model
from rest_framework import serializers

from . import mail as mail_helpers
from . import rbac
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

User = get_user_model()

# Fields set by the ORM / views; not accepted from untrusted clients.
AUDITED_READ_ONLY = (
    "id",
    "created_at",
    "updated_at",
    "created_by",
    "updated_by",
)


class UserSummarySerializer(serializers.ModelSerializer):
    """Compact user representation for nested or expanded responses."""

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name")
        read_only_fields = fields


class UserSerializer(serializers.ModelSerializer):
    """
    Full CRUD for the auth User model. Password is write-only; never returned.
    """

    password = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "is_staff",
            "is_superuser",
            "date_joined",
            "last_login",
            "password",
        )
        read_only_fields = ("id", "date_joined", "last_login")

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        if not password:
            raise serializers.ValidationError(
                {"password": "This field is required when creating a user."}
            )
        return User.objects.create_user(password=password, **validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class SiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class AgencySerializer(serializers.ModelSerializer):
    class Meta:
        model = Agency
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class StorageLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = StorageLocation
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class UnitOfMeasureSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnitOfMeasure
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Profil utilisateur exposé via `/api/user-profiles/`.

    `role` (lecture & écriture) : slug RBAC (`Role.code`). En lecture, dérivé
    du `UserRole` lié ; en écriture, upsert le `UserRole` correspondant.

    `role_label` (lecture seule) : libellé humain (FR) du rôle courant.

    `notify_user` (write-only) : envoie un e-mail HTML à l’utilisateur après enregistrement
    (uniquement si la valeur est explicitement `true` dans le JSON).

    `notify_email_sent` (lecture) : présent seulement sur la réponse d’un create/update
    qui demandait une notification — indique si l’e-mail a bien été accepté par le backend
    (voir logs si SMTP / console).
    """

    _NOTIFY_EMAIL_RESULT_UNSET = object()

    user_detail = UserSummarySerializer(source="user", read_only=True)
    role = serializers.ChoiceField(
        choices=rbac.get_role_choices(),
        required=False,
        allow_null=True,
    )
    role_label = serializers.SerializerMethodField()
    notify_user = serializers.BooleanField(
        write_only=True,
        required=False,
        allow_null=True,
    )
    scoped_project_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=True,
        write_only=True,
    )
    scoped_storage_location_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=True,
        write_only=True,
    )

    class Meta:
        model = UserProfile
        fields = (
            "id",
            "user",
            "user_detail",
            "role",
            "role_label",
            "site",
            "job_title",
            "phone",
            "pref_language",
            "pref_timezone",
            "pref_date_format",
            "pref_display_density",
            "pref_currency",
            "scoped_project_ids",
            "scoped_storage_location_ids",
            "invite_token",
            "invited_at",
            "activated_at",
            "created_at",
            "updated_at",
            "created_by",
            "updated_by",
            "notify_user",
        )
        read_only_fields = AUDITED_READ_ONLY + ("role_label",)
        extra_kwargs = {
            "invite_token": {"write_only": True},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._notify_email_result = self._NOTIFY_EMAIL_RESULT_UNSET

    def get_role_label(self, instance: UserProfile) -> str | None:
        return rbac.get_user_role_label(instance.user)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # Le champ `role` est défini comme `ChoiceField` pour la validation en
        # écriture ; en lecture on l'écrase par le slug réel du `UserRole`.
        ret["role"] = rbac.get_user_role_code(instance.user)
        ret["scoped_project_ids"] = [
            str(x) for x in instance.scoped_projects.values_list("id", flat=True)
        ]
        ret["scoped_storage_location_ids"] = [
            str(x)
            for x in instance.scoped_storage_locations.values_list("id", flat=True)
        ]
        if self._notify_email_result is not self._NOTIFY_EMAIL_RESULT_UNSET:
            # Helpers now return `(sent: bool, delivery_kind: str)` ; préserver
            # la rétrocompat (bool nu quand l'envoi a été shunté côté create/update).
            result = self._notify_email_result
            if isinstance(result, tuple) and len(result) == 2:
                sent, delivery = result
                ret["notify_email_sent"] = bool(sent)
                ret["notify_email_delivery"] = delivery
            else:
                ret["notify_email_sent"] = bool(result)
        return ret

    def _apply_role(self, user, role_code: str | None) -> None:
        """Crée/met à jour le `UserRole` du `user` selon le slug demandé.

        - `role_code` est un slug `Role.code` (déjà validé par le `ChoiceField`).
        - `None` est interprété comme « ne pas changer » (cohérent avec
          `partial=True` côté DRF). Pour _retirer_ un rôle, l'API dédiée
          `DELETE /api/user-roles/{id}/` reste disponible.
        """
        if role_code is None:
            return
        role = Role.objects.filter(code=role_code).first()
        if role is None:
            raise serializers.ValidationError(
                {"role": f"Rôle inconnu : {role_code}."}
            )
        UserRole.objects.update_or_create(
            user=user,
            defaults={"role": role},
        )

    def create(self, validated_data):
        want_notify = validated_data.pop("notify_user", None) is True
        role_code = validated_data.pop("role", None)
        scoped_p = validated_data.pop("scoped_project_ids", None)
        scoped_s = validated_data.pop("scoped_storage_location_ids", None)
        self._notify_email_result = self._NOTIFY_EMAIL_RESULT_UNSET
        instance = super().create(validated_data)
        if scoped_p is not None:
            instance.scoped_projects.set(
                Project.objects.filter(id__in=scoped_p)
            )
        if scoped_s is not None:
            instance.scoped_storage_locations.set(
                StorageLocation.objects.filter(id__in=scoped_s)
            )
        self._apply_role(instance.user, role_code)
        if want_notify:
            fresh = (
                UserProfile.objects.select_related("user", "site")
                .filter(pk=instance.pk)
                .first()
            )
            if fresh is not None:
                self._notify_email_result = mail_helpers.send_access_update_notification_email(
                    profile=fresh,
                    request=self.context.get("request"),
                )
            else:
                self._notify_email_result = False
        return instance

    def update(self, instance, validated_data):
        want_notify = validated_data.pop("notify_user", None) is True
        role_code = validated_data.pop("role", None)
        scoped_p = validated_data.pop("scoped_project_ids", None)
        scoped_s = validated_data.pop("scoped_storage_location_ids", None)
        self._notify_email_result = self._NOTIFY_EMAIL_RESULT_UNSET
        instance = super().update(instance, validated_data)
        if scoped_p is not None:
            instance.scoped_projects.set(
                Project.objects.filter(id__in=scoped_p)
            )
        if scoped_s is not None:
            instance.scoped_storage_locations.set(
                StorageLocation.objects.filter(id__in=scoped_s)
            )
        self._apply_role(instance.user, role_code)
        if want_notify:
            fresh = (
                UserProfile.objects.select_related("user", "site")
                .filter(pk=instance.pk)
                .first()
            )
            if fresh is not None:
                self._notify_email_result = mail_helpers.send_access_update_notification_email(
                    profile=fresh,
                    request=self.context.get("request"),
                )
            else:
                self._notify_email_result = False
        return instance


class InviteUserSerializer(serializers.Serializer):
    """
    Champs pour `POST /users/invite/` (création compte + profil + e-mail d’invitation).
    """

    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150, allow_blank=True, default="")
    last_name = serializers.CharField(max_length=150, allow_blank=True, default="")
    role = serializers.ChoiceField(choices=rbac.get_role_choices())
    site = serializers.UUIDField(allow_null=True, required=False)
    job_title = serializers.CharField(max_length=255, allow_blank=True, default="")
    phone = serializers.CharField(max_length=64, allow_blank=True, default="")
    scoped_project_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=True,
    )
    scoped_storage_location_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=True,
    )

    def validate_email(self, value: str) -> str:
        v = (value or "").strip().lower()
        if User.objects.filter(email__iexact=v).exists():
            raise serializers.ValidationError(
                "Un compte avec cette adresse e-mail existe déjà."
            )
        return v

    def validate_site(self, value):
        if value is None:
            return value
        if not Site.objects.filter(pk=value).exists():
            raise serializers.ValidationError("Site introuvable.")
        return value

    def validate_scoped_project_ids(self, value: list) -> list:
        if not value:
            return value
        found = set(Project.objects.filter(id__in=value).values_list("id", flat=True))
        missing = [str(x) for x in value if x not in found]
        if missing:
            raise serializers.ValidationError(
                f"Chantier(s) introuvable(s) : {', '.join(missing)}"
            )
        return value

    def validate_scoped_storage_location_ids(self, value: list) -> list:
        if not value:
            return value
        found = set(
            StorageLocation.objects.filter(id__in=value).values_list("id", flat=True)
        )
        missing = [str(x) for x in value if x not in found]
        if missing:
            raise serializers.ValidationError(
                f"Emplacement(s) introuvable(s) : {', '.join(missing)}"
            )
        return value


class MeUserReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "date_joined",
            "last_login",
        )
        read_only_fields = fields


class MeProfileReadSerializer(serializers.ModelSerializer):
    """Vue lecture seule du profil pour `/api/me/`.

    `role` et `role_label` sont **dérivés du `UserRole`** (système RBAC).
    Le frontend conserve les mêmes noms de champs qu'avant la migration.
    """

    role = serializers.SerializerMethodField()
    role_label = serializers.SerializerMethodField()
    site_name = serializers.CharField(source="site.name", read_only=True, allow_null=True)
    scoped_project_ids = serializers.SerializerMethodField()
    scoped_storage_location_ids = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = (
            "id",
            "role",
            "role_label",
            "job_title",
            "phone",
            "site",
            "site_name",
            "pref_language",
            "pref_timezone",
            "pref_date_format",
            "pref_display_density",
            "pref_currency",
            "scoped_project_ids",
            "scoped_storage_location_ids",
        )
        read_only_fields = fields

    def get_role(self, instance: UserProfile) -> str | None:
        return rbac.get_user_role_code(instance.user)

    def get_role_label(self, instance: UserProfile) -> str | None:
        return rbac.get_user_role_label(instance.user)

    def get_scoped_project_ids(self, instance: UserProfile) -> list[str]:
        return [
            str(x) for x in instance.scoped_projects.values_list("id", flat=True)
        ]

    def get_scoped_storage_location_ids(self, instance: UserProfile) -> list[str]:
        return [
            str(x) for x in instance.scoped_storage_locations.values_list("id", flat=True)
        ]


class MeUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(
        required=False, allow_blank=True, max_length=150
    )
    last_name = serializers.CharField(
        required=False, allow_blank=True, max_length=150
    )
    job_title = serializers.CharField(
        required=False, allow_blank=True, max_length=255
    )
    phone = serializers.CharField(
        required=False, allow_blank=True, max_length=64
    )
    site = serializers.UUIDField(allow_null=True, required=False)
    pref_language = serializers.ChoiceField(
        choices=UserProfile.LanguagePref.choices,
        required=False,
    )
    pref_timezone = serializers.ChoiceField(
        choices=UserProfile.TimezonePref.choices,
        required=False,
    )
    pref_date_format = serializers.ChoiceField(
        choices=UserProfile.DateFormatPref.choices,
        required=False,
    )
    pref_display_density = serializers.ChoiceField(
        choices=UserProfile.DisplayDensityPref.choices,
        required=False,
    )
    pref_currency = serializers.ChoiceField(
        choices=UserProfile.CurrencyPref.choices,
        required=False,
    )

    def validate_email(self, value):
        request = self.context.get("request")
        if not request or not request.user:
            return value
        if (
            User.objects.filter(email__iexact=value)
            .exclude(pk=request.user.pk)
            .exists()
        ):
            raise serializers.ValidationError(
                "Cette adresse e-mail est déjà utilisée par un autre compte."
            )
        return value

    def validate_site(self, value):
        if value is None:
            return value
        if not Site.objects.filter(pk=value).exists():
            raise serializers.ValidationError("Site introuvable.")
        return value

    def apply(self, user, profile):
        data = self.validated_data
        if "email" in data:
            user.email = data["email"]
        if "first_name" in data:
            user.first_name = data["first_name"]
        if "last_name" in data:
            user.last_name = data["last_name"]
        user.save()

        if "job_title" in data:
            profile.job_title = data["job_title"]
        if "phone" in data:
            profile.phone = data["phone"]
        if "site" in data:
            site_id = data["site"]
            if site_id is None:
                profile.site = None
            else:
                profile.site = Site.objects.get(pk=site_id)
        for key in (
            "pref_language",
            "pref_timezone",
            "pref_date_format",
            "pref_display_density",
            "pref_currency",
        ):
            if key in data:
                setattr(profile, key, data[key])
        profile.save()


def build_me_response(user, profile) -> dict:
    profile = (
        UserProfile.objects.select_related("user", "site")
        .prefetch_related("scoped_projects", "scoped_storage_locations")
        .get(pk=profile.pk)
    )
    return {
        "user": MeUserReadSerializer(user).data,
        "profile": MeProfileReadSerializer(profile).data,
        # Permissions effectives de l'utilisateur, dérivées du RBAC. Le frontend
        # peut s'en servir pour conditionner les actions sensibles (afficher
        # "Inviter", "Valider un mouvement", etc.). Liste vide si pas de rôle.
        "permissions": rbac.get_user_permissions(user),
    }


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(
        write_only=True,
        min_length=8,
    )


class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class StockBalanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = StockBalance
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class ProjectResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectResource
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class StockMovementSerializer(serializers.ModelSerializer):
    class Meta:
        model = StockMovement
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class ItemProjectAssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ItemProjectAssignment
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class OrganizationSettingsSerializer(serializers.ModelSerializer):
    """`smtp_password` is write-only; `smtp_has_password` indicates a stored password."""

    smtp_has_password = serializers.SerializerMethodField()

    class Meta:
        model = OrganizationSettings
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY
        extra_kwargs = {
            "smtp_password": {
                "write_only": True,
                "required": False,
                "allow_blank": True,
                "style": {"input_type": "password"},
            },
        }

    def get_smtp_has_password(self, obj: OrganizationSettings) -> bool:
        return bool((obj.smtp_password or "").strip())

    def validate(self, attrs):
        inst = self.instance
        enabled = attrs.get("smtp_enabled", inst.smtp_enabled if inst else False)
        host = attrs.get("smtp_host", (inst.smtp_host if inst else "") or "")
        if enabled and not (host or "").strip():
            raise serializers.ValidationError(
                {"smtp_host": "Requis pour activer l’envoi SMTP."}
            )
        return attrs


class IntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Integration
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class RolePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolePermission
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


class ActivityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityEvent
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY
