from rest_framework import viewsets

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
from .serializers import (
    ActivityEventSerializer,
    AgencySerializer,
    CategorySerializer,
    IntegrationSerializer,
    ItemProjectAssignmentSerializer,
    ItemSerializer,
    OrganizationSettingsSerializer,
    PermissionSerializer,
    ProjectResourceSerializer,
    ProjectSerializer,
    RolePermissionSerializer,
    RoleSerializer,
    SiteSerializer,
    StockBalanceSerializer,
    StockMovementSerializer,
    StorageLocationSerializer,
    UnitOfMeasureSerializer,
    UserProfileSerializer,
    UserRoleSerializer,
)


class SetAuditUsersMixin:
    """Set created_by / updated_by from request.user when authenticated."""

    def perform_create(self, serializer):
        user = (
            self.request.user if self.request.user.is_authenticated else None
        )
        serializer.save(created_by=user, updated_by=user)

    def perform_update(self, serializer):
        user = (
            self.request.user if self.request.user.is_authenticated else None
        )
        serializer.save(updated_by=user)


class SiteViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Site.objects.all()
    serializer_class = SiteSerializer


class AgencyViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Agency.objects.all()
    serializer_class = AgencySerializer


class StorageLocationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = StorageLocation.objects.all()
    serializer_class = StorageLocationSerializer


class UnitOfMeasureViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = UnitOfMeasure.objects.all()
    serializer_class = UnitOfMeasureSerializer


class CategoryViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class UserProfileViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = UserProfile.objects.select_related("user", "site").all()
    serializer_class = UserProfileSerializer


class ItemViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Item.objects.select_related("category", "unit").all()
    serializer_class = ItemSerializer


class StockBalanceViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = StockBalance.objects.select_related(
        "item", "storage_location"
    ).all()
    serializer_class = StockBalanceSerializer


class ProjectViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Project.objects.select_related(
        "agency", "manager", "works_supervisor"
    ).all()
    serializer_class = ProjectSerializer


class ProjectResourceViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = ProjectResource.objects.select_related("project").all()
    serializer_class = ProjectResourceSerializer


class StockMovementViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = StockMovement.objects.select_related(
        "item",
        "source_storage_location",
        "destination_storage_location",
        "project",
    ).all()
    serializer_class = StockMovementSerializer


class ItemProjectAssignmentViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = ItemProjectAssignment.objects.select_related(
        "item", "project"
    ).all()
    serializer_class = ItemProjectAssignmentSerializer


class OrganizationSettingsViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = OrganizationSettings.objects.all()
    serializer_class = OrganizationSettingsSerializer


class IntegrationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer


class RoleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer


class PermissionViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer


class RolePermissionViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = RolePermission.objects.select_related("role", "permission").all()
    serializer_class = RolePermissionSerializer


class UserRoleViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = UserRole.objects.select_related("user", "role").all()
    serializer_class = UserRoleSerializer


class ActivityEventViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    queryset = ActivityEvent.objects.select_related(
        "created_by", "updated_by"
    ).all()
    serializer_class = ActivityEventSerializer
