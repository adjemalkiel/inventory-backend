from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"sites", views.SiteViewSet, basename="site")
router.register(r"users", views.UserViewSet, basename="user")
router.register(r"agencies", views.AgencyViewSet, basename="agency")
router.register(
    r"storage-locations",
    views.StorageLocationViewSet,
    basename="storage-location",
)
router.register(
    r"units-of-measure",
    views.UnitOfMeasureViewSet,
    basename="unit-of-measure",
)
router.register(r"categories", views.CategoryViewSet, basename="category")
router.register(
    r"user-profiles",
    views.UserProfileViewSet,
    basename="user-profile",
)
router.register(r"items", views.ItemViewSet, basename="item")
router.register(
    r"stock-balances",
    views.StockBalanceViewSet,
    basename="stock-balance",
)
router.register(r"projects", views.ProjectViewSet, basename="project")
router.register(
    r"project-resources",
    views.ProjectResourceViewSet,
    basename="project-resource",
)
router.register(
    r"stock-movements",
    views.StockMovementViewSet,
    basename="stock-movement",
)
router.register(
    r"item-project-assignments",
    views.ItemProjectAssignmentViewSet,
    basename="item-project-assignment",
)
router.register(
    r"organization-settings",
    views.OrganizationSettingsViewSet,
    basename="organization-settings",
)
router.register(
    r"integrations",
    views.IntegrationViewSet,
    basename="integration",
)
router.register(r"roles", views.RoleViewSet, basename="role")
router.register(r"permissions", views.PermissionViewSet, basename="permission")
router.register(
    r"role-permissions",
    views.RolePermissionViewSet,
    basename="role-permission",
)
router.register(r"user-roles", views.UserRoleViewSet, basename="user-role")
router.register(
    r"activity-events",
    views.ActivityEventViewSet,
    basename="activity-event",
)

urlpatterns = [
    path("auth/login/", views.auth_login, name="auth-login"),
    path("auth/refresh/", views.auth_refresh, name="auth-refresh"),
    path("auth/logout/", views.auth_logout, name="auth-logout"),
    path("auth/activate/", views.auth_activate, name="auth-activate"),
    path(
        "auth/password-reset/",
        views.auth_password_reset_request,
        name="auth-password-reset",
    ),
    path(
        "auth/password-reset/confirm/",
        views.auth_password_reset_confirm,
        name="auth-password-reset-confirm",
    ),
    path("me/", views.me, name="me"),
    path("me/change-password/", views.me_change_password, name="me-change-password"),
] + router.urls
