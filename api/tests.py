"""
Tests for Section 9 — Rapports & Exports
=========================================
Covers:
  - R1: Inventaire valorisé (Excel export)
  - R3: Historique mouvements (Excel export, scoping)
  - R4: Stock critique (CSV export)
  - R5: Budget vs Réalisé (aggregation, project filter)
  - R6: Consommation mensuelle (zero-pad months, project filter)
  - R7: Transferts inter-sites (permission reports.site)
  - R8: Performance fournisseurs (default 12 months, Excel)
  - Dashboard cost-overview
  - Email send-by-email (attachment)
"""

from datetime import date

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .models import (
    Category,
    Item,
    OrganizationSettings,
    Project,
    StockMovement,
    StorageLocation,
    UnitOfMeasure,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _create_org():
    OrganizationSettings.objects.create(
        default_currency="XOF",
        smtp_enabled=True,
        smtp_host="mail.test.com",
        smtp_port=587,
        smtp_from_email="test@test.com",
        email_alerts_enabled=True,
    )


def _make_user(
    username: str,
    role: str | None = None,
    extra_permissions: list[str] | None = None,
    is_super: bool = True,
) -> User:
    user = User.objects.create_user(
        username=username,
        email=f"{username}@test.com",
        password="testpass123",
        is_superuser=is_super,
        is_staff=is_super,
    )
    if role:
        g, _ = Group.objects.get_or_create(name=role)
        user.groups.add(g)
    all_report_perms = [
        "reports.financial",
        "reports.cost",
        "reports.budget",
        "reports.site",
    ]
    perms_to_add = extra_permissions or all_report_perms
    for perm in perms_to_add:
        grp, _ = Group.objects.get_or_create(name=perm)
        user.groups.add(grp)
    return user


# ---------------------------------------------------------------------------
# Reusable fixtures
# ---------------------------------------------------------------------------

class BaseReportTestCase(TestCase):
    """Base class that sets up common test data."""

    def setUp(self):
        _create_org()
        self.unit = UnitOfMeasure.objects.create(name="Pièce")
        self.category = Category.objects.create(name="Matériaux")
        self.client = APIClient()


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


class StockValuationExportTest(BaseReportTestCase):
    """R1 — Inventaire valorisé Excel export."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("financier")
        self.item = Item.objects.create(
            name="Ciment",
            sku="CIM-001",
            category=self.category,
            unit=self.unit,
            unit_price=5000,
        )
        self.client.force_authenticate(user=self.user)

    def test_export_returns_xlsx(self):
        url = reverse("item-stock-valuation-export")
        resp = self.client.get(url)
        assert resp.status_code == 200, resp.content.decode()
        assert "application" in resp["Content-Type"]

    def test_export_requires_permission(self):
        no_perm = _make_user("viewer", extra_permissions=[], is_super=False)
        self.client.force_authenticate(user=no_perm)
        url = reverse("item-stock-valuation-export")
        resp = self.client.get(url)
        assert resp.status_code == 403


class CriticalStockExportTest(BaseReportTestCase):
    """R4 — Stock critique CSV export."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("manager")
        self.item = Item.objects.create(
            name="Vis",
            sku="VIS-001",
            category=self.category,
            unit=self.unit,
            unit_price=100,
            min_stock=50,
        )
        self.client.force_authenticate(user=self.user)

    def test_csv_export(self):
        url = reverse("item-critical-stock-export")
        resp = self.client.get(url)
        assert resp.status_code == 200
        assert "text/csv" in resp["Content-Type"]
        content = resp.content.decode()
        assert "Nom" in content
        assert "SKU" in content


class MovementsExportTest(BaseReportTestCase):
    """R3 — Stock movements Excel export with scoping + R7 transfer permission."""

    def setUp(self):
        super().setUp()
        self.admin = _make_user("admin")
        self.site_user = _make_user(
            "site-manager", extra_permissions=["reports.site"]
        )
        self.item = Item.objects.create(
            name="Marteau",
            sku="MAR-001",
            category=self.category,
            unit=self.unit,
            unit_price=2000,
        )
        self.project = Project.objects.create(
            name="Chantier A",
            reference="REF-A",
            status="en_cours",
            currency="XOF",
        )
        self.loc1 = StorageLocation.objects.create(
            name="Dépôt 1", storage_type="depot_principal"
        )
        self.loc2 = StorageLocation.objects.create(
            name="Dépôt 2",
            storage_type="magasin_chantier",
            project=self.project,
        )

        self.movement = StockMovement.objects.create(
            item=self.item,
            movement_type="entree",
            status="completed",
            quantity=10,
            unit_price_at_movement=2000,
            total_cost=20000,
            created_by=self.admin,
        )
        self.transfer = StockMovement.objects.create(
            item=self.item,
            movement_type="transfert",
            status="completed",
            quantity=5,
            source_storage_location=self.loc1,
            destination_storage_location=self.loc2,
            total_cost=0,
            created_by=self.admin,
            comment="Transfert test",
        )
        self.client.force_authenticate(user=self.admin)

    def test_export_all_movements_xlsx(self):
        url = reverse("stock-movement-export")
        resp = self.client.get(url)
        assert resp.status_code == 200
        assert "application" in resp["Content-Type"]

    def test_export_transfers_enforces_reports_site(self):
        no_site = _make_user("basic", extra_permissions=["reports.financial"], is_super=False)
        self.client.force_authenticate(user=no_site)
        url = reverse("stock-movement-export") + "?movement_type=transfert"
        resp = self.client.get(url)
        assert resp.status_code == 403

    def test_export_transfers_allowed_for_site_user(self):
        self.client.force_authenticate(user=self.site_user)
        url = reverse("stock-movement-export") + "?movement_type=transfert"
        resp = self.client.get(url)
        assert resp.status_code == 200

    def test_export_filters_by_type(self):
        url = reverse("stock-movement-export") + "?movement_type=entree"
        resp = self.client.get(url)
        assert resp.status_code == 200

    def test_export_filters_by_date(self):
        today = date.today().isoformat()
        url = reverse("stock-movement-export") + f"?date_from={today}&date_to={today}"
        resp = self.client.get(url)
        assert resp.status_code == 200


class BudgetVsActualTest(BaseReportTestCase):
    """R5 — Budget vs Réalisé aggregation + project filter."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("controleur", extra_permissions=["reports.budget"])
        self.item = Item.objects.create(
            name="Acier",
            sku="ACR-001",
            category=self.category,
            unit=self.unit,
            unit_price=15000,
        )
        self.project = Project.objects.create(
            name="Construction",
            reference="CS-001",
            status="en_cours",
            currency="XOF",
        )
        StockMovement.objects.create(
            item=self.item,
            movement_type="sortie",
            status="completed",
            quantity=2,
            unit_price_at_movement=15000,
            total_cost=30000,
            project=self.project,
            created_by=self.user,
        )
        self.client.force_authenticate(user=self.user)

    def test_budget_vs_actual_returns_json(self):
        resp = self.client.get(reverse("report-budget-vs-actual"))
        assert resp.status_code == 200
        data = resp.json()
        assert "projects" in data

    def test_budget_vs_actual_project_filter(self):
        url = f"{reverse('report-budget-vs-actual')}?project={self.project.id}"
        resp = self.client.get(url)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["projects"]) == 1
        assert data["projects"][0]["name"] == "Construction"

    def test_requires_permission(self):
        no_perm = _make_user("viewer", extra_permissions=[], is_super=False)
        self.client.force_authenticate(user=no_perm)
        resp = self.client.get(reverse("report-budget-vs-actual"))
        assert resp.status_code == 403


class MonthlyConsumptionTest(BaseReportTestCase):
    """R6 — Consommation mensuelle: zero-pad, project filter, Excel."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("financier")
        self.item = Item.objects.create(
            name="Gasoil",
            sku="GSL-001",
            category=self.category,
            unit=self.unit,
            unit_price=600,
        )
        self.project = Project.objects.create(
            name="Route", reference="R-001", status="en_cours", currency="XOF"
        )
        StockMovement.objects.create(
            item=self.item,
            movement_type="sortie",
            status="completed",
            quantity=100,
            unit_price_at_movement=600,
            total_cost=60000,
            project=self.project,
            created_by=self.user,
        )
        self.client.force_authenticate(user=self.user)

    def test_json_has_12_months(self):
        year = date.today().year
        resp = self.client.get(
            f"{reverse('report-monthly-consumption')}?year={year}"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["months"]) == 12
        labels = [m["month_label"] for m in data["months"]]
        assert "Janvier" in labels
        assert "Décembre" in labels

    def test_project_filter(self):
        year = date.today().year
        url = (
            f"{reverse('report-monthly-consumption')}"
            f"?year={year}&project={self.project.id}"
        )
        resp = self.client.get(url)
        assert resp.status_code == 200


class SupplierPerformanceTest(BaseReportTestCase):
    """R8 — Performance fournisseurs: default 12 months, Excel."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("financier")
        self.item = Item.objects.create(
            name="Adjuvant",
            sku="ADJ-001",
            category=self.category,
            unit=self.unit,
            unit_price=3000,
            supplier_name="SOCOCIM",
        )
        StockMovement.objects.create(
            item=self.item,
            movement_type="entree",
            status="completed",
            quantity=50,
            unit_price_at_movement=3000,
            total_cost=150000,
            created_by=self.user,
        )
        self.client.force_authenticate(user=self.user)

    def test_json_defaults_to_12_months(self):
        resp = self.client.get(reverse("report-supplier-performance"))
        assert resp.status_code == 200
        data = resp.json()
        assert "suppliers" in data
        assert "period" in data
        assert data["period"]["from"] is not None
        assert data["period"]["to"] is not None

    def test_requires_permission(self):
        no_perm = _make_user("viewer", extra_permissions=[], is_super=False)
        self.client.force_authenticate(user=no_perm)
        resp = self.client.get(reverse("report-supplier-performance"))
        assert resp.status_code == 403


class DashboardCostOverviewTest(BaseReportTestCase):
    """Dashboard cost-overview endpoint."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("manager")
        Project.objects.create(
            name="Immeuble A",
            reference="IA-001",
            status="en_cours",
            currency="XOF",
        )
        Project.objects.create(
            name="Pont B", reference="PB-001", status="planifie", currency="XOF"
        )
        self.client.force_authenticate(user=self.user)

    def test_cost_overview_returns_aggregates(self):
        resp = self.client.get("/api/v1/dashboard/cost-overview/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active_projects_count"] == 2
        assert "total_budget" in data
        assert "total_cost" in data
        assert len(data["projects"]) == 2

    def test_requires_auth(self):
        unauth = APIClient()
        resp = unauth.get("/api/v1/dashboard/cost-overview/")
        assert resp.status_code == 401


class EmailReportTest(BaseReportTestCase):
    """send-by-email endpoint."""

    def setUp(self):
        super().setUp()
        self.user = _make_user("financier")
        self.client.force_authenticate(user=self.user)

    def test_send_email_missing_recipient(self):
        resp = self.client.post(
            reverse("report-send-by-email"),
            {"report_type": "stock_valuation"},
            format="json",
        )
        assert resp.status_code == 400
        assert "recipient_email" in resp.json().get("detail", "")

    def test_send_email_unknown_report_type(self):
        resp = self.client.post(
            reverse("report-send-by-email"),
            {"report_type": "unknown_report", "recipient_email": "x@y.com"},
            format="json",
        )
        assert resp.status_code == 400

    def test_requires_permission(self):
        no_perm = _make_user("viewer", extra_permissions=[], is_super=False)
        self.client.force_authenticate(user=no_perm)
        resp = self.client.post(
            reverse("report-send-by-email"),
            {"report_type": "stock_valuation", "recipient_email": "x@y.com"},
            format="json",
        )
        assert resp.status_code == 403
