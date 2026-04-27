import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class AuditedModel(models.Model):
    """Abstract base: UUID primary key, audit users, and timestamps."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(editable=False, default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="%(app_label)s_%(class)s_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="%(app_label)s_%(class)s_updated",
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.created_at = timezone.now()
        self.updated_at = timezone.now()
        super().save(*args, **kwargs)


class Site(AuditedModel):
    """User / org attachment site (e.g. Dépôt Cotonou)."""

    name = models.CharField(max_length=255)
    code = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Agency(AuditedModel):
    """Project centre de rattachement (e.g. Agence Littoral Nord)."""

    name = models.CharField(max_length=255)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "Agencies"

    def __str__(self) -> str:
        return self.name


class StorageLocation(AuditedModel):
    class StorageType(models.TextChoices):
        DEPOT_PRINCIPAL = "depot_principal", "Dépôt Principal"
        MAGASIN_CHANTIER = "magasin_chantier", "Magasin Chantier"
        ZONE_TEMPORAIRE = "zone_temporaire", "Zone Temporaire"
        CONTENEUR_MOBILE = "conteneur_mobile", "Conteneur Mobile"

    name = models.CharField(max_length=255)
    storage_type = models.CharField(
        max_length=32,
        choices=StorageType.choices,
        default=StorageType.DEPOT_PRINCIPAL,
    )
    address = models.CharField(max_length=512, blank=True)
    manager_name = models.CharField(max_length=255, blank=True)
    manager_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="managed_storage_locations",
    )
    capacity_m2 = models.DecimalField(
        max_digits=12, decimal_places=2, null=True, blank=True
    )
    notes = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class UnitOfMeasure(AuditedModel):
    name = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "Units of measure"

    def __str__(self) -> str:
        return self.name


class Category(AuditedModel):
    name = models.CharField(max_length=255)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="children",
    )

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "Categories"

    def __str__(self) -> str:
        return self.name


class UserProfile(AuditedModel):
    """
    Profil métier d'un compte. Le **rôle** n'est plus stocké ici : il est géré
    exclusivement par le système RBAC (`Role` + `UserRole` + `Permission` +
    `RolePermission`). Voir `api.rbac.ROLE_DEFINITIONS` pour le catalogue.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    site = models.ForeignKey(
        Site,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="users",
    )
    job_title = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=64, blank=True)

    class LanguagePref(models.TextChoices):
        FR_FR = "fr-FR", "Français (France)"
        EN_US = "en-US", "English (US)"

    class TimezonePref(models.TextChoices):
        EUROPE_PARIS = "Europe/Paris", "(GMT+01:00) Paris"
        AFRICA_PORTO_NOVO = "Africa/Porto-Novo", "(GMT+01:00) Cotonou / Porto-Novo"
        UTC = "UTC", "UTC"

    class DateFormatPref(models.TextChoices):
        DMY = "dmy", "JJ/MM/AAAA"
        MDY = "mdy", "MM/JJ/AAAA"
        YMD = "ymd", "AAAA-MM-JJ (ISO)"

    class DisplayDensityPref(models.TextChoices):
        STANDARD = "standard", "Standard (Editorial)"
        COMPACT = "compact", "Compact"
        COMFORTABLE = "comfortable", "Lecture confortable"

    class CurrencyPref(models.TextChoices):
        EUR = "EUR", "Euro (€)"
        XOF = "XOF", "Franc CFA (BCEAO)"
        USD = "USD", "Dollar (US)"
        CNY = "CNY", "Yuan renminbi (¥)"

    pref_language = models.CharField(
        max_length=16,
        choices=LanguagePref.choices,
        default=LanguagePref.FR_FR,
    )
    pref_timezone = models.CharField(
        max_length=64,
        choices=TimezonePref.choices,
        default=TimezonePref.EUROPE_PARIS,
    )
    pref_date_format = models.CharField(
        max_length=16,
        choices=DateFormatPref.choices,
        default=DateFormatPref.DMY,
    )
    pref_display_density = models.CharField(
        max_length=32,
        choices=DisplayDensityPref.choices,
        default=DisplayDensityPref.STANDARD,
    )
    pref_currency = models.CharField(
        max_length=8,
        choices=CurrencyPref.choices,
        default=CurrencyPref.EUR,
    )

    invite_token = models.CharField(max_length=128, blank=True)
    invited_at = models.DateTimeField(null=True, blank=True)
    activated_at = models.DateTimeField(null=True, blank=True)

    # Réinitialisation de mot de passe (« oublié » ou action admin) — jeton
    # stocké côté serveur, lien `/reset-password?reset=…` (plus de uid/token Django).
    password_reset_token = models.CharField(max_length=128, blank=True)
    password_reset_sent_at = models.DateTimeField(null=True, blank=True)

    scoped_projects = models.ManyToManyField(
        "Project",
        blank=True,
        related_name="scoped_user_profiles",
        help_text=(
            "Chantiers assignés : restreint la liste / fiches visibles pour les rôles "
            "périmètre chantier (ex. chef de chantier). Si vide, repli sur manager / "
            "conducteur de travaux du projet."
        ),
    )
    scoped_storage_locations = models.ManyToManyField(
        "StorageLocation",
        blank=True,
        related_name="scoped_user_profiles",
        help_text=(
            "Emplacements de stock assignés : restreint inventaire et mouvements pour "
            "les rôles périmètre dépôt (ex. magasinier). Si vide, repli sur "
            "`StorageLocation.manager_user`."
        ),
    )

    def __str__(self) -> str:
        return f"{self.user.get_username()} profile"


class Item(AuditedModel):
    name = models.CharField(max_length=255)
    sku = models.CharField(max_length=128, unique=True)
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        related_name="items",
    )
    description = models.TextField(blank=True)
    subcategory_label = models.CharField(max_length=255, blank=True)
    brand = models.CharField(max_length=255, blank=True)
    image_url = models.URLField(max_length=1024, blank=True)
    purchase_date = models.DateField(null=True, blank=True)
    warranty_label = models.CharField(max_length=128, blank=True)
    supplier_name = models.CharField(max_length=255, blank=True)
    unit = models.ForeignKey(
        UnitOfMeasure,
        on_delete=models.PROTECT,
        related_name="items",
    )
    min_stock = models.DecimalField(max_digits=14, decimal_places=3, default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.sku})"


class StockBalance(AuditedModel):
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="balances")
    storage_location = models.ForeignKey(
        StorageLocation,
        on_delete=models.CASCADE,
        related_name="stock_balances",
    )
    zone_label = models.CharField(max_length=255, blank=True)
    quantity = models.DecimalField(max_digits=14, decimal_places=3, default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["item", "storage_location", "zone_label"],
                name="uniq_item_location_zone",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.item.sku} @ {self.storage_location_id}"


class Project(AuditedModel):
    class ProjectType(models.TextChoices):
        RESIDENTIEL = "residentiel_collectif", "Résidentiel Collectif"
        TERTIAIRE = "tertiaire", "Tertiaire / Bureaux"
        INFRA = "infrastructure_publique", "Infrastructure Publique"

    class Priority(models.TextChoices):
        HAUTE = "haute", "Haute"
        MOYENNE = "moyenne", "Moyenne"
        BASSE = "basse", "Basse"

    class Criticality(models.TextChoices):
        STANDARD = "standard", "Standard"
        SENSIBLE = "sensible", "Sensible"
        CRITIQUE = "critique", "Critique"

    class TrackingMode(models.TextChoices):
        PROGRESS = "progress", "Avancement %"
        HOURS = "hours", "Heures réelles"

    name = models.CharField(max_length=255)
    reference = models.CharField(max_length=128, unique=True)
    project_type = models.CharField(
        max_length=32,
        choices=ProjectType.choices,
        default=ProjectType.RESIDENTIEL,
    )
    client_name = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=128, default="En cours de création")
    priority = models.CharField(
        max_length=16,
        choices=Priority.choices,
        default=Priority.HAUTE,
    )
    description = models.TextField(blank=True)
    address = models.CharField(max_length=512, blank=True)
    city = models.CharField(max_length=128, blank=True)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    agency = models.ForeignKey(
        Agency,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="projects",
    )
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="managed_projects",
    )
    works_supervisor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="supervised_projects",
    )
    budget_amount = models.DecimalField(
        max_digits=16, decimal_places=2, null=True, blank=True
    )
    max_staff = models.PositiveIntegerField(null=True, blank=True)
    criticality = models.CharField(
        max_length=16,
        choices=Criticality.choices,
        default=Criticality.STANDARD,
    )
    tracking_mode = models.CharField(
        max_length=16,
        choices=TrackingMode.choices,
        default=TrackingMode.PROGRESS,
    )
    auto_alerts_enabled = models.BooleanField(default=True)
    movement_slips_enabled = models.BooleanField(default=True)
    rfid_sync_enabled = models.BooleanField(default=False)
    ai_assistance_enabled = models.BooleanField(default=True)
    is_draft = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name


class ProjectResource(AuditedModel):
    class ResourceKind(models.TextChoices):
        EQUIPMENT = "equipment", "Matériel"
        SUBCONTRACT = "subcontract", "Sous-traitance"

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="resources",
    )
    resource_kind = models.CharField(
        max_length=32,
        choices=ResourceKind.choices,
        default=ResourceKind.EQUIPMENT,
    )
    name = models.CharField(max_length=255)
    availability_date = models.DateField(null=True, blank=True)
    headcount = models.PositiveIntegerField(null=True, blank=True)
    status_label = models.CharField(max_length=128, blank=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.project.reference})"


class StockMovement(AuditedModel):
    class MovementType(models.TextChoices):
        ENTREE = "entree", "Entrée (Stockage)"
        SORTIE = "sortie", "Sortie (Usage Chantier)"
        TRANSFERT = "transfert", "Transfert Inter-Sites"
        RETOUR = "retour", "Retour de Chantier"

    movement_type = models.CharField(max_length=16, choices=MovementType.choices)
    item = models.ForeignKey(
        Item,
        on_delete=models.PROTECT,
        related_name="movements",
    )
    quantity = models.DecimalField(max_digits=14, decimal_places=3)
    source_storage_location = models.ForeignKey(
        StorageLocation,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="outgoing_movements",
    )
    destination_storage_location = models.ForeignKey(
        StorageLocation,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="incoming_movements",
    )
    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="stock_movements",
    )
    comment = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.movement_type} {self.quantity} {self.item.sku}"


class ItemProjectAssignment(AuditedModel):
    item = models.ForeignKey(
        Item,
        on_delete=models.CASCADE,
        related_name="project_assignments",
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="item_assignments",
    )
    assigned_at = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["item", "project"],
                name="uniq_item_project_assignment",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.item.sku} → {self.project.reference}"


class OrganizationSettings(AuditedModel):
    """Singleton-style app settings (use one row, e.g. pk=1)."""

    global_low_stock_threshold_percent = models.PositiveSmallIntegerField(
        default=15,
        help_text="Notify when stock falls below this percentage of capacity.",
    )
    expiry_alert_days_before = models.PositiveIntegerField(default=30)
    expiry_alerts_enabled = models.BooleanField(default=False)
    predictive_analysis_enabled = models.BooleanField(default=True)
    auto_reports_enabled = models.BooleanField(default=False)

    smtp_enabled = models.BooleanField(
        default=False,
        help_text="When set, use these SMTP settings instead of the server .env e-mail config.",
    )
    smtp_host = models.CharField(max_length=255, blank=True, default="")
    smtp_port = models.PositiveIntegerField(default=587)
    smtp_use_tls = models.BooleanField(default=True)
    smtp_use_ssl = models.BooleanField(
        default=False,
        help_text="Implicit TLS (e.g. port 465). Leave off if using STARTTLS (587).",
    )
    smtp_user = models.CharField(max_length=255, blank=True, default="")
    smtp_password = models.CharField(max_length=255, blank=True, default="")
    smtp_from_email = models.EmailField(
        blank=True,
        help_text="Adresse d’expéditeur pour l’e-mail (sinon paramètre par défaut du serveur).",
    )

    class Meta:
        verbose_name_plural = "Organization settings"

    def __str__(self) -> str:
        return "Organization settings"


class Integration(AuditedModel):
    provider_key = models.CharField(max_length=64)
    display_name = models.CharField(max_length=255)
    is_connected = models.BooleanField(default=False)
    config = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["display_name"]

    def __str__(self) -> str:
        return self.display_name


class Role(AuditedModel):
    """
    Rôle RBAC. `code` est le slug stable utilisé par l'API et le frontend
    (ex. `magasinier`, `chef_chantier`) ; `name` est le libellé humain (FR).
    """

    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Permission(AuditedModel):
    code = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["code"]

    def __str__(self) -> str:
        return self.code


class RolePermission(AuditedModel):
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="role_permissions",
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        related_name="role_permissions",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission"],
                name="uniq_role_permission",
            ),
        ]


class UserRole(AuditedModel):
    """
    Affectation d'un rôle à un utilisateur. **Un seul rôle par utilisateur**
    est autorisé (contrainte `uniq_user_one_role`) ; les multi-rôles seront
    introduits ultérieurement avec une UI dédiée.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_roles",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="user_roles",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user"],
                name="uniq_user_one_role",
            ),
        ]


class ActivityEvent(models.Model):
    """Audit log entry: actor is created_by; edits tracked via updated_* if ever mutable."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    entity_type = models.CharField(max_length=64)
    entity_id = models.CharField(max_length=64)
    action = models.CharField(max_length=128)
    payload = models.JSONField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="activity_events",
    )
    created_at = models.DateTimeField(editable=False, default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="activity_events_updated",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["entity_type", "entity_id"]),
        ]

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.created_at = timezone.now()
        self.updated_at = timezone.now()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.action} {self.entity_type}:{self.entity_id}"
