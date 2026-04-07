from django.contrib.auth import get_user_model
from rest_framework import serializers

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
    user_detail = UserSummarySerializer(source="user", read_only=True)

    class Meta:
        model = UserProfile
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY
        extra_kwargs = {
            "invite_token": {"write_only": True},
        }


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
    class Meta:
        model = OrganizationSettings
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY


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
