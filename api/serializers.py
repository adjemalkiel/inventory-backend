from django.contrib.auth import get_user_model
from rest_framework import serializers

from . import mail as mail_helpers
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
    `notify_user` (write-only) : envoie un e-mail HTML à l’utilisateur après enregistrement
    (uniquement si la valeur est explicitement `true` dans le JSON).

    `notify_email_sent` (lecture) : présent seulement sur la réponse d’un create/update
    qui demandait une notification — indique si l’e-mail a bien été accepté par le backend
    (voir logs si SMTP / console).
    """

    _NOTIFY_EMAIL_RESULT_UNSET = object()

    user_detail = UserSummarySerializer(source="user", read_only=True)
    notify_user = serializers.BooleanField(
        write_only=True,
        required=False,
        allow_null=True,
    )

    class Meta:
        model = UserProfile
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY
        extra_kwargs = {
            "invite_token": {"write_only": True},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._notify_email_result = self._NOTIFY_EMAIL_RESULT_UNSET

    def create(self, validated_data):
        want_notify = validated_data.pop("notify_user", None) is True
        self._notify_email_result = self._NOTIFY_EMAIL_RESULT_UNSET
        instance = super().create(validated_data)
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
        self._notify_email_result = self._NOTIFY_EMAIL_RESULT_UNSET
        instance = super().update(instance, validated_data)
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

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if self._notify_email_result is not self._NOTIFY_EMAIL_RESULT_UNSET:
            ret["notify_email_sent"] = bool(self._notify_email_result)
        return ret


class InviteUserSerializer(serializers.Serializer):
    """
    Champs pour `POST /users/invite/` (création compte + profil + e-mail d’invitation).
    """

    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150, allow_blank=True, default="")
    last_name = serializers.CharField(max_length=150, allow_blank=True, default="")
    role = serializers.ChoiceField(choices=UserProfile.Role.choices)
    site = serializers.UUIDField(allow_null=True, required=False)
    job_title = serializers.CharField(max_length=255, allow_blank=True, default="")

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
    role_label = serializers.CharField(source="get_role_display", read_only=True)
    site_name = serializers.CharField(source="site.name", read_only=True, allow_null=True)

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
        )
        read_only_fields = fields


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
        .get(pk=profile.pk)
    )
    return {
        "user": MeUserReadSerializer(user).data,
        "profile": MeProfileReadSerializer(profile).data,
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
