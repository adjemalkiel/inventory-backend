# Rapport de Spécifications — Bâtir Pro
## Section 6 : Lieux de Stockage

---

### 6.1 Contexte & justification

Édifice Durable opère sur **plusieurs dépôts simultanément** (dépôts principaux à Cotonou, magasins de chantier sur les 5 à 10 sites actifs). Chaque lieu de stockage est un centre de coût et de responsabilité distinct : un magasinier ne gère que son dépôt, un chef de chantier supervise le stock de son site, la direction a une vision consolidée.

Le client a exprimé le besoin de savoir **ce qui est stocké où**, de suivre la **valeur du stock par dépôt**, et d'identifier les **ruptures critiques par lieu** avant que l'approvisionnement ne soit bloqué. Ces besoins apparaissent dans le Dashboard (Section 2 — endpoint `stock-distribution/` déjà spécifié) et dans le contexte des mouvements (Section 4 — champs `source_storage_location` et `destination_storage_location`).

**État actuel du code :**

| Composant | État | Détail |
|-----------|------|--------|
| Modèle `StorageLocation` | ✅ Solide | Hérite de `AuditedModel`, UUID PK, champs métier partiels. |
| `StorageLocation.storage_type` | ✅ Bon | 4 types : `depot_principal`, `magasin_chantier`, `zone_temporaire`, `conteneur_mobile`. |
| `StorageLocation.manager_user` | ✅ FK User | + `manager_name` texte pour rétrocompat. |
| `StorageLocation.capacity_m2` | ⚠️ Partiel | Surface en m² présente. Manque la `city`, le rattachement à un projet, les coordonnées GPS. |
| `StorageLocationViewSet` | ⚠️ Partiel | Scope magasinier correct. Pas de `filter_backends`, `search_fields` ni `ordering_fields`. |
| `StorageLocationSerializer` | ⚠️ Basique | Champs `__all__` bruts. Aucune annotation de stock, de valeur, de comptage critique. |
| `StorageLocationAccess` | ✅ Excellent | Matrice RBAC complète, scoping M2M magasinier. |
| `StockBalance.zone_label` | ✅ Partiel | Permet de subdiviser un lieu par zone (texte libre). Contrainte unique `(item, storage_location, zone_label)`. Pas de modèle `StorageZone` dédié (suffisant pour le pilote). |
| `StoragePage` (frontend) | ❌ Mock | 100 % hardcodé — KPIs, liste, zones stratégiques. |
| `NewStoragePage` (frontend) | ⚠️ Partiel | Appelle `apiServices.storageLocations.create()` mais `manager_user` n'est pas un vrai dropdown d'utilisateurs, pas de `city`, pas de `project`. |
| `StorageDetailPage` (frontend) | ❌ Absent | Route `/storage/:id` non définie. |

---

### 6.2 Taxonomie des lieux de stockage

| Type | Code | Description | Rattachement |
|------|------|-------------|--------------|
| Dépôt Principal | `depot_principal` | Entrepôt fixe de l'agence, gros volumes | Agence |
| Magasin Chantier | `magasin_chantier` | Stockage temporaire sur site | Projet (FK nullable) |
| Zone Temporaire | `zone_temporaire` | Espace provisoire (conteneur, hangar loué) | Libre |
| Conteneur Mobile | `conteneur_mobile` | Conteneur transportable entre chantiers | Libre / Projet |

> Les types sont déjà dans le code. La relation optionnelle avec un `Project` (pour `magasin_chantier` et `conteneur_mobile`) est la principale addition de cette section.

---

### 6.3 Spécifications Backend

#### 6.3.1 Enrichissement du modèle `StorageLocation`

**Champs à ajouter (nouvelle migration)** :

| Champ | Type Django | Description | Null/Blank |
|-------|-------------|-------------|-----------|
| `city` | `CharField(max_length=128, blank=True)` | Ville / localisation textuelle | `blank=True` |
| `agency` | `ForeignKey('Agency', null=True, blank=True, on_delete=SET_NULL, related_name='storage_locations')` | Rattachement agence | `null=True, blank=True` |
| `project` | `ForeignKey('Project', null=True, blank=True, on_delete=SET_NULL, related_name='storage_locations')` | Rattachement chantier (pour `magasin_chantier`) | `null=True, blank=True` |
| `latitude` | `DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)` | Coordonnée GPS — latitude | `null=True, blank=True` |
| `longitude` | `DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)` | Coordonnée GPS — longitude | `null=True, blank=True` |

**Champs existants à conserver sans modification** : `name`, `storage_type`, `address`, `manager_name`, `manager_user`, `capacity_m2`, `notes`, `is_active`.

> **Rétrocompatibilité `manager_name`** : Conserver le champ texte tel quel. Si `manager_user` est renseigné dans le serializer, synchroniser automatiquement `manager_name = instance.manager_user.get_full_name() or instance.manager_user.username`. Ne pas supprimer `manager_name` avant la Section 10 (Paramètres).

**Migration :**

```python
# api/migrations/0021_storagelocation_v2.py
class Migration(migrations.Migration):
    dependencies = [
        ("api", "0020_normalize_project_status"),
    ]
    operations = [
        migrations.AddField(
            model_name="storagelocation",
            name="city",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="agency",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=models.deletion.SET_NULL,
                related_name="storage_locations",
                to="api.agency",
            ),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="project",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=models.deletion.SET_NULL,
                related_name="storage_locations",
                to="api.project",
            ),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="latitude",
            field=models.DecimalField(
                blank=True, decimal_places=6, max_digits=9, null=True
            ),
        ),
        migrations.AddField(
            model_name="storagelocation",
            name="longitude",
            field=models.DecimalField(
                blank=True, decimal_places=6, max_digits=9, null=True
            ),
        ),
    ]
```

---

#### 6.3.2 Serializer enrichi `StorageLocationSerializer`

Le serializer actuel retourne les champs bruts. Ajouter des **annotations calculées en lecture seule** pour éviter les N+1 sur la liste et alimenter les KPI cards du frontend sans appel supplémentaire.

```python
class StorageLocationSerializer(serializers.ModelSerializer):
    # Champs relationnels dénormalisés (lecture seule)
    agency_name = serializers.CharField(
        source="agency.name", read_only=True, allow_null=True
    )
    project_name = serializers.CharField(
        source="project.name", read_only=True, allow_null=True
    )
    project_reference = serializers.CharField(
        source="project.reference", read_only=True, allow_null=True
    )
    manager_display = serializers.SerializerMethodField()

    # Champs annotés (calculés dans get_queryset(), lecture seule sur la liste)
    stock_items_count = serializers.IntegerField(read_only=True, default=0)
    stock_value = serializers.DecimalField(
        max_digits=18, decimal_places=2, read_only=True, allow_null=True
    )
    critical_count = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = StorageLocation
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY

    def get_manager_display(self, obj):
        if obj.manager_user:
            name = obj.manager_user.get_full_name().strip()
            return name or obj.manager_user.get_username()
        return obj.manager_name or None

    def update(self, instance, validated_data):
        # Synchronisation rétrocompat manager_name
        if "manager_user" in validated_data and validated_data["manager_user"]:
            mu = validated_data["manager_user"]
            validated_data.setdefault(
                "manager_name",
                mu.get_full_name().strip() or mu.get_username(),
            )
        return super().update(instance, validated_data)

    def create(self, validated_data):
        if "manager_user" in validated_data and validated_data["manager_user"]:
            mu = validated_data["manager_user"]
            validated_data.setdefault(
                "manager_name",
                mu.get_full_name().strip() or mu.get_username(),
            )
        return super().create(validated_data)
```

**Queryset annoté dans `StorageLocationViewSet.get_queryset()` :**

```python
from django.db.models import (
    Case, Count, DecimalField, F, IntegerField,
    OuterRef, Q, Subquery, Sum, Value, When,
)
from django.db.models.functions import Coalesce

def get_queryset(self):
    # Annotation : nombre d'articles distincts stockés ici
    # Annotation : valeur totale = SUM(balance.quantity × item.unit_price)
    # Annotation : articles critiques = SUM(balance < min_stock)
    qs = StorageLocation.objects.select_related(
        "agency", "project", "manager_user"
    ).annotate(
        stock_items_count=Count(
            "stock_balances__item", distinct=True
        ),
        stock_value=Coalesce(
            Sum(
                F("stock_balances__quantity") * F("stock_balances__item__unit_price"),
                output_field=DecimalField(max_digits=18, decimal_places=2),
            ),
            Value(0, output_field=DecimalField(max_digits=18, decimal_places=2)),
        ),
        critical_count=Count(
            "stock_balances__item",
            filter=Q(
                stock_balances__quantity__gt=0,
                stock_balances__quantity__lt=F("stock_balances__item__min_stock"),
            ),
            distinct=True,
        ),
    )
    # Scope magasinier — logique existante conservée
    u = self.request.user
    r = rbac.get_user_role_code(u)
    if r == "magasinier":
        sids = user_scope.user_scoped_storage_location_ids(u)
        if sids is not None:
            return qs.filter(id__in=sids)
        return qs.filter(manager_user_id=u.id)
    return qs
```

> **Note performance** : l'annotation `stock_value` nécessite que `item.unit_price` soit renseigné (Section 3). Si `unit_price` est `null`, le produit est `null` et Coalesce le ramène à 0. Acceptable pour le pilote.

---

#### 6.3.3 Endpoint KPI par lieu — `GET /api/v1/storage-locations/{id}/summary/`

Agrégation complète pour l'en-tête du détail d'un lieu de stockage.

```python
@action(detail=True, methods=["get"], url_path="summary")
def summary(self, request, pk=None):
    """KPIs agrégés pour un lieu de stockage (Section 6.3.3)."""
    location = self.get_object()

    from django.db.models import Count, Sum
    from django.db.models.functions import Coalesce
    from django.utils import timezone
    from datetime import timedelta

    today = timezone.now().date()

    # Balances de ce lieu
    balances_qs = StockBalance.objects.filter(storage_location=location)

    # Articles distincts stockés ici (quantité > 0)
    items_count = balances_qs.filter(quantity__gt=0).values("item").distinct().count()

    # Valeur totale du stock
    stock_value = balances_qs.aggregate(
        total=Coalesce(
            Sum(F("quantity") * F("item__unit_price"),
                output_field=DecimalField(max_digits=18, decimal_places=2)),
            Value(Decimal("0")),
        )
    )["total"]

    # Articles en rupture (quantité ≤ 0)
    stockout_count = balances_qs.filter(quantity__lte=0).values("item").distinct().count()

    # Articles critiques (0 < quantité < min_stock)
    critical_count = balances_qs.filter(
        quantity__gt=0,
        quantity__lt=F("item__min_stock"),
    ).values("item").distinct().count()

    # Mouvements sur ce lieu (entrées + sorties)
    movements_qs = StockMovement.objects.filter(
        Q(source_storage_location=location) |
        Q(destination_storage_location=location)
    )
    movements_today = movements_qs.filter(created_at__date=today).count()
    movements_week = movements_qs.filter(
        created_at__date__gte=today - timedelta(days=7)
    ).count()

    # Zones utilisées (zone_label distincts, excluant la zone vide)
    zones = list(
        balances_qs.exclude(zone_label="")
        .values_list("zone_label", flat=True)
        .distinct()
        .order_by("zone_label")
    )

    # Capacité (calcul à affiner en Section 7 ; null pour le pilote si capacity_m2 non défini)
    capacity_percent = None  # Placeholder — alimenté en Section 7

    return Response({
        "location_id": str(location.id),
        "name": location.name,
        "storage_type": location.storage_type,
        "is_active": location.is_active,
        "items_count": items_count,
        "stock_value": str(stock_value),
        "stockout_count": stockout_count,
        "critical_count": critical_count,
        "movements_today": movements_today,
        "movements_week": movements_week,
        "zones": zones,
        "zones_count": len(zones),
        "capacity_m2": str(location.capacity_m2) if location.capacity_m2 else None,
        "capacity_percent": capacity_percent,
        "has_coordinates": bool(location.latitude and location.longitude),
    })
```

---

#### 6.3.4 Filtrage, recherche, tri sur `StorageLocationViewSet`

```python
class StorageLocationViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, access.StorageLocationAccess]
    serializer_class = StorageLocationSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["storage_type", "is_active", "agency", "project"]
    search_fields = ["name", "address", "city", "manager_name"]
    ordering_fields = ["name", "storage_type", "city", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        # ... code annoté du §6.3.2
```

---

#### 6.3.5 Zones de stockage — gestion via `zone_label`

Le champ `StockBalance.zone_label` permet de subdiviser un lieu en zones nommées (ex. : "Zone A", "Étagère 3", "Allée Nord"). Cette approche par texte libre est **suffisante pour le pilote** et évite une migration de rupture.

> **Phase 2 (post-pilote)** : Si le client souhaite gérer les zones comme des entités (avec capacité propre, responsable, QR code), on créera alors un modèle `StorageZone` avec une FK depuis `StockBalance.zone`. Pour l'instant, `zone_label` reste un `CharField`.

**Endpoint dédié : `GET /api/v1/storage-locations/{id}/zones/`**

Retourne les zones actives d'un lieu avec leur stock agrégé.

```python
@action(detail=True, methods=["get"], url_path="zones")
def zones(self, request, pk=None):
    """Liste des zones utilisées dans ce lieu avec stock agrégé."""
    location = self.get_object()

    zones_data = (
        StockBalance.objects.filter(storage_location=location)
        .values("zone_label")
        .annotate(
            items_count=Count("item", distinct=True),
            total_quantity=Sum("quantity"),
        )
        .order_by("zone_label")
    )

    return Response({
        "location_id": str(location.id),
        "zones": [
            {
                "zone_label": z["zone_label"] or "(Zone principale)",
                "items_count": z["items_count"],
                "total_quantity": str(z["total_quantity"]),
            }
            for z in zones_data
        ]
    })
```

---

#### 6.3.6 Endpoint stock par lieu — `GET /api/v1/stock-balances/?storage_location={id}`

Déjà fonctionnel via les filtres `StockBalanceViewSet` (Section 3 — `filterset_fields = ['item', 'storage_location']`). Ajouter le filtre `zone_label` :

```python
# api/views.py — dans StockBalanceViewSet
class StockBalanceViewSet(viewsets.ReadOnlyModelViewSet):
    ...
    filterset_fields = ["item", "storage_location", "zone_label"]
    search_fields = ["item__name", "item__sku", "zone_label"]
    ordering_fields = ["quantity", "item__name", "updated_at"]
    ordering = ["item__name"]
```

---

### 6.4 Spécifications Frontend

#### 6.4.1 Page Liste des Lieux (`/storage`) — `StoragePage.tsx`

**État actuel :** 100 % hardcodé. Toute la page est à connecter.

**A. En-tête KPI (3 cartes) :**

Les données viennent de `GET /api/v1/storage-locations/` (liste annotée) :

| KPI | Calcul côté frontend depuis la liste |
|-----|--------------------------------------|
| Lieux actifs | `locations.filter(l => l.is_active).length` |
| Valeur stock totale | `SUM(locations.stock_value)` (champ annoté) |
| Articles critiques | `SUM(locations.critical_count)` (champ annoté) |

**B. Section "Zones Stratégiques" :**

Les 3 dépôts de type `depot_principal` ou les 3 lieux ayant la plus haute `stock_value`. Ajouter un badge coloré par type :

| Type | Couleur | Icône |
|------|---------|-------|
| `depot_principal` | bleu | warehouse |
| `magasin_chantier` | vert | hard-hat |
| `zone_temporaire` | orange | clock |
| `conteneur_mobile` | gris | box |

**C. Liste complète :**

```typescript
// Fetch
const data = await apiServices.storageLocations.rawList({
  ordering: 'name',
  page_size: 100,  // faible volume (<50 lieux)
});
```

Colonnes du tableau :

| Colonne | Source |
|---------|--------|
| Lieu / Type | `name` + `storage_type` badge |
| Ville | `city` |
| Statut | `is_active` badge Actif/Inactif |
| Articles | `stock_items_count` (annoté) |
| Valeur stock | `stock_value` formaté FCFA |
| Articles critiques | `critical_count` badge rouge si > 0 |
| Responsable | `manager_display` |
| Chantier lié | `project_reference` (si renseigné) |
| Actions | Voir / Modifier |

**D. Filtres :**

| Filtre | Paramètre API |
|--------|---------------|
| Type | `?storage_type=depot_principal\|magasin_chantier\|...` |
| Statut | `?is_active=true\|false` |
| Recherche | `?search=cotonou` (nom, ville, adresse, responsable) |

**E. Bouton "Nouveau lieu" :**

Visible pour `administrateur` uniquement (vérifier via `permissions` de `/api/v1/me/`).

---

#### 6.4.2 Page Nouveau Lieu (`/storage/new`) — `NewStoragePage.tsx`

**État actuel :** Appelle `apiServices.storageLocations.create()` mais plusieurs champs sont manquants. À enrichir.

**Modifications au formulaire :**

| Champ UI | Champ API | Obligatoire |
|----------|-----------|-------------|
| Nom du lieu | `name` | Oui |
| Type | `storage_type` (dropdown) | Oui |
| Ville | `city` | Non |
| Adresse | `address` | Non |
| **Agence** | `agency` (dropdown depuis `/api/v1/agencies/`) | Non |
| **Chantier associé** | `project` (dropdown depuis `/api/v1/projects/`, visible si type = `magasin_chantier` ou `conteneur_mobile`) | Non |
| Responsable | `manager_user` (dropdown depuis `/api/v1/user-profiles/`) | Non |
| Surface (m²) | `capacity_m2` | Non |
| **Latitude** | `latitude` | Non (optionnel, aide à la carte) |
| **Longitude** | `longitude` | Non |
| Notes | `notes` | Non |
| Actif | `is_active` (toggle, défaut `true`) | Oui |

> **Champ `manager_user`** : Remplacer le champ texte libre `manager` actuel par un `<Select>` chargé depuis `apiServices.userProfiles.list()`. Synchroniser `manager_name` automatiquement côté backend (§6.3.2).

> **Champ conditionnel `project`** : N'afficher le dropdown "Chantier associé" que si `storage_type` vaut `magasin_chantier` ou `conteneur_mobile`.

---

#### 6.4.3 Page Détail d'un Lieu (`/storage/:id`) — `StorageDetailPage.tsx` *(à créer)*

Nouvelle route à créer dans `src/App.tsx` :

```typescript
<Route path="/storage/:id" element={<StorageDetailPage />} />
```

> ⚠️ Déclarer `/storage/new` **avant** `/storage/:id` dans `App.tsx` pour que React Router donne la priorité au chemin statique.

**Structure de la page — onglets :**

**Onglet 1 — Vue d'ensemble :**

- En-tête : nom, type (badge), ville, adresse, responsable, statut actif/inactif
- KPI cards depuis `GET /api/v1/storage-locations/{id}/summary/` :
  - Articles stockés
  - Valeur du stock
  - Ruptures
  - Articles critiques
  - Mouvements aujourd'hui
- Section "Zones" (depuis le champ `zones` du summary) : liste des zones avec items/quantité
- Informations complémentaires : agence, chantier lié, surface (m²), notes
- Carte (optionnel pilote) : si `latitude` + `longitude` renseignés, afficher un marqueur sur une carte OpenStreetMap (Leaflet.js ou équivalent léger)

**Onglet 2 — Stock :**

- Fetch `GET /api/v1/stock-balances/?storage_location={id}&ordering=item__name&page_size=100`
- Tableau : Article | SKU | Catégorie | Zone | Quantité | Unité | Valeur | Statut stock
- Filtre par zone (`?zone_label=...`) si des zones existent
- Filtre par statut stock (rupture / critique / disponible)
- Badge coloré sur chaque ligne selon `stock_status` : vert/orange/rouge
- KPI résumé en bas : Valeur totale, nbre articles, nbre ruptures

**Onglet 3 — Mouvements :**

- Fetch `GET /api/v1/stock-movements/?source_storage_location={id}&ordering=-created_at&page=1`
  et `GET /api/v1/stock-movements/?destination_storage_location={id}&...`
- Combinaison OU côté frontend (deux appels séparés ou filtre `storage_location={id}` si l'endpoint supporte une FK OR — voir note ci-dessous)
- Tableau : Date | Référence | Type | Article | Quantité | Source → Destination | Chantier | Statut
- Bouton "Enregistrer un mouvement" → `/inventory/new-movement?destinationLocationId={id}`

> **Note développeur** : Plutôt que deux appels séparés, ajouter un filtre `storage_location` qui cherche dans **les deux FK** (source OU destination) :
>
> ```python
> # api/filters.py — dans StockMovementFilter
> storage_location = django_filters.UUIDFilter(method='filter_by_location')
>
> def filter_by_location(self, queryset, name, value):
>     return queryset.filter(
>         Q(source_storage_location=value) |
>         Q(destination_storage_location=value)
>     )
> ```

**Onglet 4 — Chantiers liés :**

- Projets dont les mouvements impliquent ce lieu (`StockMovement.project.distinct()` filtrés par ce `storage_location`)
- Fetch `GET /api/v1/stock-movements/?storage_location={id}&page_size=1000` → dédoublonner sur `project`
- Afficher : Référence chantier, Nom, Statut, Nombre de sorties depuis ce lieu
- Lien vers `/projects/{id}` pour chaque chantier

---

#### 6.4.4 Mise à jour de `NewMovementPage` pour le `zone_label`

Dans `NewMovementPage.tsx`, les dropdowns source/destination de lieu ne gèrent pas les zones. Pour le pilote, **ne pas bloquer sur ce point**. Ajouter un champ optionnel texte libre "Zone (optionnel)" qui alimente `zone_label` dans la creation d'un `StockBalance` lors du mouvement.

> Ce champ n'est pas dans le payload de `StockMovement` — le `zone_label` est un champ de `StockBalance`. Il sera géré implicitement par `_apply_movement_to_balances()` qui utilise `zone_label=''` par défaut. Le champ UI peut être ajouté en Phase 2.

---

#### 6.4.5 Statuts et badges couleur (TypeScript)

Ajouter dans `src/types/api.ts` les champs manquants :

```typescript
export interface StorageLocation extends ApiAudit {
  name: string;
  storage_type: StorageType;
  address: string;
  city: string;                        // NOUVEAU
  agency: UUID | null;                  // NOUVEAU
  project: UUID | null;                 // NOUVEAU
  latitude: string | null;              // NOUVEAU
  longitude: string | null;             // NOUVEAU
  manager_name: string;
  manager_user: UserId | null;
  capacity_m2: string | null;
  notes: string;
  is_active: boolean;
  // Champs annotés (présents sur la liste)
  agency_name?: string | null;          // NOUVEAU
  project_name?: string | null;         // NOUVEAU
  project_reference?: string | null;    // NOUVEAU
  manager_display?: string | null;      // NOUVEAU
  stock_items_count?: number;           // NOUVEAU
  stock_value?: string | null;          // NOUVEAU
  critical_count?: number;             // NOUVEAU
}
```

Et l'interface `StorageLocationSummary` pour l'action `summary/` :

```typescript
export interface StorageLocationSummary {
  location_id: UUID;
  name: string;
  storage_type: StorageType;
  is_active: boolean;
  items_count: number;
  stock_value: string;
  stockout_count: number;
  critical_count: number;
  movements_today: number;
  movements_week: number;
  zones: string[];
  zones_count: number;
  capacity_m2: string | null;
  capacity_percent: number | null;
  has_coordinates: boolean;
}
```

**Ajouter dans `apiServices` (`src/lib/api/services.ts`) :**

```typescript
storageLocations: {
  ...createCrudService<StorageLocation>('storage-locations'),
  summary: (id: UUID) =>
    unwrap(http.get<StorageLocationSummary>(`storage-locations/${id}/summary/`)),
  zones: (id: UUID) =>
    unwrap(http.get<{ location_id: UUID; zones: ZoneInfo[] }>(`storage-locations/${id}/zones/`)),
},
```

---

### 6.5 Dépendances

| Dépendance | Impact |
|------------|--------|
| Section 1 (Auth) ✅ | RBAC complet : `StorageLocationAccess`, scoping magasinier via M2M `scoped_storage_locations`. |
| Section 3 (Inventaire) ✅ | `StockBalance` lié à `StorageLocation`. `unit_price` sur `Item` nécessaire pour `stock_value`. |
| Section 4 (Mouvements) ✅ | `source_storage_location` et `destination_storage_location` alimentent les mouvements par lieu. |
| Section 5 (Projets) ✅ | La FK `StorageLocation.project` relie un magasin chantier à son projet. |
| Section 7 (Coûts) ⏳ | `capacity_percent` sera calculé depuis les coûts et le volume défini sur le lieu. |
| Section 9 (Rapports) ⏳ | Rapport d'inventaire par lieu (stock valorisé, mouvements, écarts physiques). |

---

### 6.6 Priorité d'implémentation

| Étape | Tâche | Estimation |
|-------|-------|------------|
| 1 | **Backend : migration** — ajout `city`, `agency`, `project`, `latitude`, `longitude` sur `StorageLocation` | 0.25 jour |
| 2 | **Backend : `StorageLocationSerializer` enrichi** — annotations, `manager_display`, sync `manager_name` | 0.5 jour |
| 3 | **Backend : `get_queryset` annoté** dans `StorageLocationViewSet` (`stock_items_count`, `stock_value`, `critical_count`) | 0.5 jour |
| 4 | **Backend : filtres + recherche** sur `StorageLocationViewSet` (`filter_backends`, `filterset_fields`, `search_fields`, `ordering_fields`) | 0.25 jour |
| 5 | **Backend : `@action summary/`** sur `StorageLocationViewSet` | 0.5 jour |
| 6 | **Backend : `@action zones/`** sur `StorageLocationViewSet` | 0.25 jour |
| 7 | **Backend : filtre `storage_location` (OU source/destination)** dans `StockMovementFilter` | 0.25 jour |
| 8 | **Backend : `StockBalanceViewSet`** — ajouter `zone_label`, `search_fields`, `ordering_fields` | 0.25 jour |
| 9 | **Frontend : types TypeScript** — enrichir `StorageLocation`, ajouter `StorageLocationSummary` | 0.25 jour |
| 10 | **Frontend : `StoragePage`** — connecter à l'API, filtres, KPI cards, liste réelle | 1.5 jours |
| 11 | **Frontend : `NewStoragePage`** — ajouter `city`, `project` conditionnel, dropdown `manager_user` | 0.5 jour |
| 12 | **Frontend : `StorageDetailPage`** — 4 onglets, KPIs, stock, mouvements, chantiers liés | 2 jours |
| **Total estimé** | | **~7 jours** |

---

### 6.7 Critères de validation (Definition of Done)

**Backend :**
- [ ] `GET /api/v1/storage-locations/` retourne `stock_items_count`, `stock_value`, `critical_count` sur chaque lieu
- [ ] `GET /api/v1/storage-locations/?storage_type=depot_principal` filtre correctement
- [ ] `GET /api/v1/storage-locations/?search=cotonou` filtre sur nom, ville, adresse, responsable
- [ ] `POST /api/v1/storage-locations/` accepte `city`, `agency`, `project`, `latitude`, `longitude`
- [ ] `POST /api/v1/storage-locations/` avec `manager_user` → `manager_name` synchronisé automatiquement
- [ ] `GET /api/v1/storage-locations/{id}/summary/` retourne les KPIs complets
- [ ] `GET /api/v1/storage-locations/{id}/zones/` retourne les zones avec leur stock agrégé
- [ ] `GET /api/v1/stock-movements/?storage_location={id}` filtre les mouvements source OU destination
- [ ] `GET /api/v1/stock-balances/?storage_location={id}&zone_label=Zone+A` filtre par zone
- [ ] Un magasinier ne voit que les lieux de son scope

**Frontend :**
- [ ] `StoragePage` n'affiche aucune donnée hardcodée ; empty state si aucun lieu
- [ ] Les 3 KPI cards (lieux actifs, valeur stock, articles critiques) affichent les données réelles
- [ ] Les filtres type/statut et la recherche sont fonctionnels
- [ ] `NewStoragePage` crée un lieu via l'API avec tous les nouveaux champs
- [ ] `NewStoragePage` : le dropdown "Chantier associé" n'apparaît que pour `magasin_chantier` et `conteneur_mobile`
- [ ] `StorageDetailPage` affiche les vraies données de l'API dans les 4 onglets
- [ ] L'onglet "Stock" affiche les balances réelles filtrables par zone
- [ ] L'onglet "Mouvements" affiche les mouvements entrants ET sortants du lieu
- [ ] Les KPIs du summary affichent `—` si la valeur est `null`
- [ ] La route `/storage/:id` est accessible et ne conflicte pas avec `/storage/new`
