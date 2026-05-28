# Rapport de Spécifications — Bâtir Pro
## Section 7 : Coûts & Budget par chantier
### Version 1 — rédigée après audit du code (Sections 1 à 6 implémentées)

---

> **Criticité : BLOQUANT.** Le suivi du coût réel par chantier est la **2ème priorité absolue** du client (Q29), juste après la traçabilité des stocks. C'est l'objectif central qui justifie l'automatisation demandée en Q15 (« Nous souhaitons automatiser ce calcul dans le logiciel »).

> **Périmètre de cette section :**
> - Méthodes de **valorisation des sorties de stock configurables** (Q17 — centrepiece, §7.2)
> - Architecture de **coût réel consolidé par chantier** (matériaux, MO, sous-traitance, location, frais généraux, pertes — Q16)
> - **Budget prévu vs réalisé** par poste et par phase (Q16)
> - **Marge par chantier** (contrat − coût réel)
> - **Historique des prix d'achat** et écarts fournisseurs (Q17)
> - **Inventaire valorisé** (valeur totale du stock — Q19)
> - Notes sur **multi-devise, TVA et taxes** (Q18 — cadrage pour le pilote)

---

### 7.1 Contexte & justification

Aujourd'hui le client calcule le coût d'un chantier sous Excel par consolidation manuelle (Q15). Il veut suivre dans le logiciel (Q16) :

- coût des matériaux consommés ;
- coût de la main-d'œuvre ;
- coût de la sous-traitance ;
- coût de location d'équipements ;
- frais généraux de chantier ;
- coûts logistiques / transport ;
- pertes, casses et écarts d'inventaire ;
- coûts par phase, lot ou poste de travail ;
- **comparaison budget prévu vs réalisé** ;
- **marge par chantier**.

Les prix d'achat varient régulièrement (Q17). Le client demande explicitement : « le **prix moyen pondéré ou autre méthode de valorisation configurable** ». C'est le point d'ancrage de cette section.

**État actuel du code (après audit Sections 1 à 6) :**

| Composant | État | Détail |
|-----------|------|--------|
| `Item.unit_price` + `currency` | ✅ Existe | `DecimalField(14,2)` nullable. Représente le **dernier prix d'achat connu**. (Section 3) |
| `StockMovement.unit_price_at_movement` + `total_cost` | ✅ Existe | `total_cost = quantity × unit_price_at_movement` calculé dans `StockMovementSerializer._computed_total_cost()`. **Mais `unit_price_at_movement` est aujourd'hui fourni par le client** (pré-rempli depuis `item.unit_price` côté frontend, §4.4.2) — aucune méthode de valorisation backend. |
| `StockMovement.status=completed` | ✅ Existe | Seuls les mouvements `completed` alimentent les coûts. (Section 4) |
| `ProjectViewSet.summary/` | ⚠️ Partiel | Calcule `cost_materials_consumed` (somme `total_cost` des sorties `completed`) et `budget_consumed_percent`. **Champs `cost_labour`, `cost_subcontracting`, `cost_rental`, `cost_total`, `margin_percent` retournés à `None` avec le commentaire « Section 7 alimentera ces champs ».** ([views.py:909-914](inventory-backend-main/api/views.py#L909-L914)) |
| `ProjectBudgetLine` | ✅ Existe | 7 `CostCategory`, FK `phase` nullable, `budget_amount`, `actual_amount` (nullable, **jamais alimenté automatiquement**). (Section 5) |
| `ProjectResource` | ❌ Incomplet | Seulement `equipment` + `subcontract`. **Pas de `main_oeuvre`, pas de champs coût** (`unit_cost`, `cost_unit`, `planned_duration`). Le §5.3.8 v2 l'avait spécifié mais ce n'est **pas implémenté** dans [models.py:550-571](inventory-backend-main/api/models.py#L550-L571). |
| `StockCostLayer` (ledger de coût) | ❌ Absent | Aucun suivi des couches de coût. Bloque FIFO et CUMP exact. |
| Config méthode de valorisation | ❌ Absent | `OrganizationSettings` n'a pas de champ `stock_valuation_method`. |
| Historique des prix d'achat | ⚠️ Dérivable | Pas de modèle dédié, mais reconstituable depuis les mouvements `entree` (`unit_price_at_movement`, `created_at`, `item__supplier`). |
| Frontend `ProjectSummary` (type) | ✅ Prêt | [api.ts:434-453](inventory-client-main/src/types/api.ts#L434-L453) contient déjà `cost_labour`, `cost_subcontracting`, `cost_rental`, `cost_total`, `margin_percent` (placeholders). |
| Frontend onglet Budget | ✅ Partiel | Affiche les `ProjectBudgetLine` (budget par catégorie). Pas de colonne « réalisé » alimentée, pas de marge. |

**Conclusion :** la plomberie de coût (champs `total_cost`, agrégation des sorties, placeholders summary) est en place. Section 7 ajoute **(1)** le moteur de valorisation configurable, **(2)** la consolidation multi-postes du coût chantier, **(3)** le budget vs réalisé et la marge.

---

### 7.2 ⭐ Méthodes de valorisation configurables (cœur de la section)

#### 7.2.1 Le problème métier

Quand des matériaux sortent du stock vers un chantier (`movement_type=sortie`), **à quel coût unitaire les facture-t-on au chantier ?** Les prix d'achat variant dans le temps (Q17), le même article a été acheté à des prix différents. Le choix de la méthode de valorisation change le coût imputé au chantier et la valeur du stock restant.

> **Principe directeur (à respecter par le dev) :** le coût unitaire d'une sortie est **calculé par le backend au moment où le mouvement passe à `completed`**, puis **figé** dans `unit_price_at_movement` et `total_cost`. La méthode de valorisation ne fait que déterminer *comment* ce coût est calculé. Une fois figé, le coût ne bouge plus, même si le prix d'achat change ensuite. C'est la garantie d'un coût chantier historiquement exact et auditable.

Aujourd'hui le frontend envoie `unit_price_at_movement`. **Section 7 retire cette responsabilité au client pour les mouvements sortants** : le champ devient calculé côté serveur pour `sortie` et `ajustement` (perte). Il reste fourni par l'utilisateur pour `entree` (= prix d'achat réel de la livraison).

#### 7.2.2 Les trois méthodes proposées

On propose **trois méthodes configurables**, couvrant du plus simple au plus rigoureux :

| Code | Nom | Principe | Pour qui |
|------|-----|----------|----------|
| `last_price` | **Dernier prix d'achat connu** | La sortie est valorisée au dernier prix d'achat de l'article (`item.unit_price`). | Démarrage du pilote, simplicité maximale, équipes non comptables. |
| `wac` | **Coût Moyen Pondéré (CUMP)** | La sortie est valorisée à la moyenne pondérée des coûts du stock encore détenu. Recalculé à chaque entrée. | **Recommandé / défaut.** Explicitement demandé en Q17 (« prix moyen pondéré »). Lisse les variations de prix. Standard comptable. |
| `fifo` | **FIFO / PEPS (Premier Entré, Premier Sorti)** | La sortie consomme d'abord les plus anciennes couches de stock, à leur coût d'achat réel. | Traçabilité fine, reflète l'ordre réel de consommation en chantier, écarts par lot. |

> On écarte volontairement **LIFO/DEPS** (Dernier Entré Premier Sorti) : non conforme aux normes comptables OHADA/IFRS applicables au contexte du client, et trompeur en période d'inflation. Ne pas l'implémenter.

#### 7.2.3 Architecture commune : le registre de couches de coût (`StockCostLayer`)

Pour servir les trois méthodes avec **une seule source de vérité**, on introduit un **registre de couches de coût** (cost ledger). Chaque entrée de stock costée crée une « couche » (quantité + coût unitaire). Chaque sortie consomme ces couches dans l'ordre FIFO.

- **`fifo`** : consomme les couches dans l'ordre → le coût figé = moyenne pondérée réelle des couches consommées.
- **`wac`** : coût figé = valeur totale des couches ouvertes ÷ quantité totale ouverte, **avant** consommation. (La consommation décrémente quand même les couches en FIFO pour garder les quantités cohérentes.)
- **`last_price`** : coût figé = `item.unit_price`. (La consommation décrémente quand même les couches.)

Ainsi, **les quantités du registre restent toujours cohérentes** quelle que soit la méthode ; seul le *nombre figé* dans `unit_price_at_movement` diffère. Cela permet aussi de **changer de méthode en cours de route** sans corrompre les données, et de produire un **inventaire valorisé** fiable (§7.4.8).

**Mouvements affectant le registre :**

| `movement_type` | Effet sur le registre de couches |
|----------------|----------------------------------|
| `entree` | **Ouvre une couche** : `quantity` au coût `unit_price_at_movement` (prix d'achat saisi). |
| `retour` | **Ouvre une couche** : `quantity` au coût courant (`item.unit_price` ou CUMP — le matériel revient en stock). |
| `ajustement` (surplus, destination) | **Ouvre une couche** : `quantity` à `item.unit_price`. |
| `sortie` | **Consomme** `quantity` en FIFO. |
| `ajustement` (perte, source) | **Consomme** `quantity` en FIFO (la valeur consommée = coût de la perte). |
| `transfert` | **Aucun effet** sur le registre (mouvement interne — le stock reste dans l'entreprise). |

> **Granularité du registre : par article (`item`), pas par emplacement.** En BTP le coût d'un article est une propriété de l'article au niveau entreprise, pas du dépôt. Les transferts inter-sites ne doivent donc pas toucher le coût. Cela simplifie aussi le modèle (une file FIFO par article au lieu d'une par couple article×lieu). Les `StockBalance` continuent de suivre les quantités **par emplacement** comme aujourd'hui ; le registre suit le **coût** au niveau article.

---

### 7.3 Spécifications Backend

#### 7.3.1 🆕 Enrichissement `ProjectResource` (prérequis — porté du §5.3.8 v2, non implémenté)

Nécessaire pour consolider les coûts MO / sous-traitance / location. **Migration `0022_projectresource_costs`.**

```python
# api/models.py — remplacer la classe ProjectResource existante
class ProjectResource(AuditedModel):
    class ResourceKind(models.TextChoices):
        EQUIPMENT   = "equipment",   "Matériel / Équipement"
        SUBCONTRACT = "subcontract", "Sous-traitance"
        MAIN_OEUVRE = "main_oeuvre", "Main d'œuvre"          # 🆕

    class CostUnit(models.TextChoices):
        JOUR    = "jour",    "par Jour"
        HEURE   = "heure",   "par Heure"
        FORFAIT = "forfait", "Forfait"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="resources")
    resource_kind = models.CharField(max_length=32, choices=ResourceKind.choices,
                                      default=ResourceKind.EQUIPMENT)
    name = models.CharField(max_length=255)
    availability_date = models.DateField(null=True, blank=True)
    headcount = models.PositiveIntegerField(null=True, blank=True)
    status_label = models.CharField(max_length=128, blank=True)

    # 🆕 Champs coût
    unit_cost = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True,
        help_text="FCFA/jour (matériel), FCFA/h (MO), FCFA forfait (sous-traitance).")
    cost_unit = models.CharField(max_length=16, choices=CostUnit.choices, blank=True)
    planned_duration = models.PositiveSmallIntegerField(null=True, blank=True,
        help_text="Durée planifiée (jours ou heures selon cost_unit).")
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["project", "resource_kind", "name"]
```

**Coût estimé d'une ressource** = `unit_cost × planned_duration` (forfait → `planned_duration` ignoré, coût = `unit_cost`). Exposé en lecture seule par le serializer (`estimated_cost`).

```python
# api/serializers.py — ProjectResourceSerializer enrichi
class ProjectResourceSerializer(serializers.ModelSerializer):
    resource_kind_label = serializers.CharField(source="get_resource_kind_display", read_only=True)
    estimated_cost = serializers.SerializerMethodField()

    class Meta:
        model = ProjectResource
        fields = "__all__"
        read_only_fields = AUDITED_READ_ONLY

    def get_estimated_cost(self, obj):
        if obj.unit_cost is None:
            return None
        if obj.cost_unit == ProjectResource.CostUnit.FORFAIT or not obj.planned_duration:
            return str(obj.unit_cost)
        return str(obj.unit_cost * obj.planned_duration)
```

Ajouter les filtres manquants sur `ProjectResourceViewSet` (porté du §5.3.11) :

```python
filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
filterset_fields = ["project", "resource_kind"]
search_fields = ["name", "status_label", "notes"]
ordering_fields = ["resource_kind", "name", "availability_date"]
ordering = ["resource_kind", "name"]
```

---

#### 7.3.2 🆕 Configuration de la méthode de valorisation (`OrganizationSettings`)

**Migration `0023_valuation_settings`.** Ajouter à `OrganizationSettings` :

```python
class StockValuationMethod(models.TextChoices):
    LAST_PRICE = "last_price", "Dernier prix d'achat connu"
    WAC        = "wac",        "Coût moyen pondéré (CUMP)"
    FIFO       = "fifo",       "FIFO / PEPS (Premier entré, premier sorti)"

stock_valuation_method = models.CharField(
    max_length=16,
    choices=StockValuationMethod.choices,
    default=StockValuationMethod.WAC,   # CUMP par défaut (recommandé, demandé Q17)
    help_text="Méthode de valorisation des sorties de stock vers les chantiers.",
)
default_currency = models.CharField(max_length=8, default="XOF")   # Q18
vat_rate_percent = models.DecimalField(max_digits=5, decimal_places=2, default=0,
    help_text="Taux de TVA par défaut appliqué aux coûts (0 = désactivé).")   # Q18
```

> **Le champ est déjà exposé** par `OrganizationSettingsSerializer` (`fields = "__all__"`), donc aucun changement de serializer. Le frontend pourra lire/écrire `stock_valuation_method` directement.

---

#### 7.3.3 🆕 Modèle `StockCostLayer` (registre de couches de coût)

**Migration `0024_stock_cost_layer`.**

```python
# api/models.py
class StockCostLayer(AuditedModel):
    """
    Couche de coût d'un article (registre FIFO / CUMP).
    Une couche est ouverte par chaque mouvement entrant costé,
    et consommée (qty_remaining décrémentée) par les mouvements sortants.
    Granularité : par article (niveau entreprise), pas par emplacement.
    """
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="cost_layers")
    source_movement = models.ForeignKey(
        "StockMovement", null=True, blank=True,
        on_delete=models.SET_NULL, related_name="opened_cost_layers",
    )
    unit_cost = models.DecimalField(max_digits=14, decimal_places=2)
    quantity_in = models.DecimalField(max_digits=14, decimal_places=3)
    quantity_remaining = models.DecimalField(max_digits=14, decimal_places=3)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["item", "occurred_at"]   # FIFO = ordre chronologique
        indexes = [models.Index(fields=["item", "occurred_at"])]

    def __str__(self):
        return f"{self.item.sku} · {self.quantity_remaining}/{self.quantity_in} @ {self.unit_cost}"
```

**Migration de backfill `0025_seed_initial_cost_layers`** : créer une couche initiale par article ayant du stock, pour ne pas casser la valorisation des stocks existants :

```python
def seed_initial_layers(apps, schema_editor):
    Item = apps.get_model("api", "Item")
    StockBalance = apps.get_model("api", "StockBalance")
    StockCostLayer = apps.get_model("api", "StockCostLayer")
    from django.db.models import Sum
    from decimal import Decimal
    for item in Item.objects.all():
        total = StockBalance.objects.filter(item=item).aggregate(s=Sum("quantity"))["s"] or Decimal("0")
        if total > 0:
            cost = item.unit_price if item.unit_price is not None else Decimal("0")
            StockCostLayer.objects.create(
                item=item, unit_cost=cost,
                quantity_in=total, quantity_remaining=total,
            )
```

---

#### 7.3.4 🆕 Service de valorisation (`api/valuation.py` — nouveau fichier)

Centralise toute la logique. Appelé depuis `_apply_movement_to_balances()` quand un mouvement passe `completed`.

```python
# api/valuation.py
from decimal import Decimal
from django.db.models import Sum, F
from .models import StockCostLayer, OrganizationSettings, StockMovement

ZERO = Decimal("0")


def _active_method() -> str:
    settings_row = OrganizationSettings.objects.first()
    return settings_row.stock_valuation_method if settings_row else "wac"


def _weighted_average_cost(item) -> Decimal:
    agg = StockCostLayer.objects.filter(item=item, quantity_remaining__gt=0).aggregate(
        qty=Sum("quantity_remaining"),
        val=Sum(F("quantity_remaining") * F("unit_cost")),
    )
    qty, val = agg["qty"] or ZERO, agg["val"] or ZERO
    return (val / qty) if qty > 0 else (item.unit_price or ZERO)


def open_layer(movement: StockMovement, unit_cost: Decimal) -> None:
    """Ouvre une couche pour un mouvement entrant (entree / retour / ajustement+)."""
    StockCostLayer.objects.create(
        item=movement.item,
        source_movement=movement,
        unit_cost=unit_cost or ZERO,
        quantity_in=movement.quantity,
        quantity_remaining=movement.quantity,
        occurred_at=movement.created_at,
        created_by=movement.created_by, updated_by=movement.updated_by,
    )


def consume_layers(item, quantity: Decimal) -> Decimal:
    """
    Consomme `quantity` dans les couches FIFO. Retourne le coût unitaire
    moyen pondéré RÉEL des couches consommées (= coût FIFO).
    Si le registre est vide/insuffisant, complète au dernier prix connu.
    """
    remaining = quantity
    consumed_value = ZERO
    layers = StockCostLayer.objects.select_for_update().filter(
        item=item, quantity_remaining__gt=0
    ).order_by("occurred_at")
    for layer in layers:
        if remaining <= 0:
            break
        take = min(layer.quantity_remaining, remaining)
        consumed_value += take * layer.unit_cost
        layer.quantity_remaining -= take
        layer.save(update_fields=["quantity_remaining", "updated_at"])
        remaining -= take
    if remaining > 0:   # registre insuffisant (stock legacy) → dernier prix
        fallback = item.unit_price or ZERO
        consumed_value += remaining * fallback
    return (consumed_value / quantity) if quantity > 0 else ZERO


def resolve_outgoing_unit_cost(item, quantity: Decimal, method: str) -> Decimal:
    """
    Coût unitaire à figer sur un mouvement sortant, selon la méthode active.
    IMPORTANT : pour wac/last_price, on consomme quand même les couches
    (cohérence des quantités) mais on renvoie le coût de la méthode.
    """
    if method == "wac":
        cost = _weighted_average_cost(item)     # AVANT consommation
        consume_layers(item, quantity)
        return cost
    if method == "last_price":
        consume_layers(item, quantity)
        return item.unit_price or ZERO
    # fifo : le coût EST le résultat de la consommation
    return consume_layers(item, quantity)
```

> **`select_for_update()`** sur les couches : même garde-fou anti-race que `_apply_movement_to_balances()` (usage mobile concurrent, Section 3/4). Tout doit tourner dans la transaction atomique déjà ouverte par `perform_create` / `approve`.

---

#### 7.3.5 ⚡ Intégration dans `_apply_movement_to_balances()`

> **Ne pas réécrire la fonction.** Elle existe ([views.py:128](inventory-backend-main/api/views.py#L128)), gère déjà entree/sortie/transfert/retour/ajustement avec `select_for_update` et transaction atomique. On **ajoute uniquement** la mise à jour du registre de coût et le figeage du coût, en réutilisant le service `valuation`.

Logique à insérer (pseudo-intégration aux branches existantes) :

```python
from . import valuation

def _apply_movement_to_balances(movement):
    # ... maj des StockBalance par type (code existant, inchangé) ...

    method = valuation._active_method()

    if movement.movement_type == "entree":
        # prix d'achat saisi par l'utilisateur
        price = movement.unit_price_at_movement or (movement.item.unit_price or Decimal("0"))
        valuation.open_layer(movement, price)
        # mettre à jour le "dernier prix connu" de l'article
        if movement.unit_price_at_movement is not None:
            movement.item.unit_price = movement.unit_price_at_movement
            movement.item.save(update_fields=["unit_price", "updated_at"])

    elif movement.movement_type == "retour":
        valuation.open_layer(movement, valuation._weighted_average_cost(movement.item))

    elif movement.movement_type == "ajustement" and movement.destination_storage_location:
        valuation.open_layer(movement, movement.item.unit_price or Decimal("0"))

    elif movement.movement_type in ("sortie",) or (
        movement.movement_type == "ajustement" and movement.source_storage_location
    ):
        unit_cost = valuation.resolve_outgoing_unit_cost(
            movement.item, movement.quantity, method
        )
        movement.unit_price_at_movement = unit_cost
        movement.total_cost = unit_cost * movement.quantity
        movement.save(update_fields=["unit_price_at_movement", "total_cost", "updated_at"])
    # transfert : aucun effet registre
```

**Conséquence sur le serializer :** `unit_price_at_movement` devient **lecture seule** pour `sortie` et `ajustement` (calculé serveur). Il reste **modifiable** pour `entree` (prix d'achat). Adapter `StockMovementSerializer` :

```python
def validate(self, attrs):
    attrs = super().validate(attrs)
    mtype = attrs.get("movement_type") or (self.instance.movement_type if self.instance else None)
    # Le prix de sortie est calculé par le moteur de valorisation, pas par le client.
    if mtype in (StockMovement.MovementType.SORTIE, StockMovement.MovementType.AJUSTEMENT):
        attrs.pop("unit_price_at_movement", None)
    # ... reste des validations existantes ...
    return attrs
```

> **Cas `approve/`** (Section 4) : quand un mouvement `pending` est approuvé, `_apply_movement_to_balances()` est appelée → la valorisation s'applique **au moment de l'approbation** (et non de la création). C'est le comportement correct : le coût figé reflète l'état du stock à l'exécution réelle. Aucun changement à faire dans l'action `approve/`, elle appelle déjà la fonction.

---

#### 7.3.6 🆕 Consolidation du coût chantier — endpoint `cost-breakdown/`

On **enrichit `ProjectViewSet.summary/`** (qui a déjà les placeholders) plutôt que de créer un endpoint concurrent, et on ajoute un endpoint détaillé `cost-breakdown/` pour l'onglet Coûts.

**Postes de coût et leur source :**

| Poste | Source backend |
|-------|----------------|
| **Matériaux consommés** | Σ `total_cost` des `StockMovement` `sortie` `completed` du projet. (déjà calculé) |
| **Pertes / casses** | Σ `total_cost` des `ajustement` (perte) `completed` rattachés au projet. |
| **Main d'œuvre** | Σ `estimated_cost` des `ProjectResource` `main_oeuvre`. |
| **Sous-traitance** | Σ `estimated_cost` des `ProjectResource` `subcontract`. |
| **Location équipements** | Σ `estimated_cost` des `ProjectResource` `equipment`. |
| **Frais généraux / logistique** | Σ `actual_amount` (sinon `budget_amount`) des `ProjectBudgetLine` catégories `frais_generaux` / `logistique`. |
| **Coût total** | Somme des postes ci-dessus. |
| **Budget total** | `project.budget_amount` (sinon Σ `ProjectBudgetLine.budget_amount`). |
| **Marge** | `contract_value − coût total` ; `margin_percent = marge ÷ contract_value × 100`. |

```python
# api/views.py — dans ProjectViewSet
@action(detail=True, methods=["get"], url_path="cost-breakdown")
def cost_breakdown(self, request, pk=None):
    project = self.get_object()
    Z = Decimal("0")

    def _sum(qs, field):
        return qs.aggregate(t=Coalesce(Sum(field),
            Value(Z, output_field=DecimalField(max_digits=18, decimal_places=2))))["t"]

    completed = StockMovement.objects.filter(
        project=project, status=StockMovement.MovementStatus.COMPLETED)
    cost_materials = _sum(completed.filter(movement_type="sortie"), "total_cost")
    cost_losses = _sum(completed.filter(movement_type="ajustement",
                       source_storage_location__isnull=False), "total_cost")

    # Ressources : coût estimé agrégé par type (calcul Python, faible volume)
    res = ProjectResource.objects.filter(project=project)
    def _res_cost(kind):
        total = Z
        for r in res.filter(resource_kind=kind):
            if r.unit_cost is None:
                continue
            if r.cost_unit == "forfait" or not r.planned_duration:
                total += r.unit_cost
            else:
                total += r.unit_cost * r.planned_duration
        return total
    cost_labour = _res_cost("main_oeuvre")
    cost_subcontracting = _res_cost("subcontract")
    cost_rental = _res_cost("equipment")

    lines = ProjectBudgetLine.objects.filter(project=project)
    cost_overhead = Z
    for line in lines.filter(category__in=["frais_generaux", "logistique"]):
        cost_overhead += (line.actual_amount if line.actual_amount is not None
                          else line.budget_amount)

    cost_total = (cost_materials + cost_losses + cost_labour
                  + cost_subcontracting + cost_rental + cost_overhead)

    budget_total = project.budget_amount or _sum(lines, "budget_amount")
    contract = project.contract_value
    margin = (contract - cost_total) if contract is not None else None
    margin_percent = (round(float(margin) / float(contract) * 100, 1)
                      if contract and contract > 0 else None)

    return Response({
        "project_id": str(project.id),
        "currency": project.currency,
        "cost_materials": str(cost_materials),
        "cost_losses": str(cost_losses),
        "cost_labour": str(cost_labour),
        "cost_subcontracting": str(cost_subcontracting),
        "cost_rental": str(cost_rental),
        "cost_overhead": str(cost_overhead),
        "cost_total": str(cost_total),
        "budget_total": str(budget_total),
        "contract_value": str(contract) if contract is not None else None,
        "margin": str(margin) if margin is not None else None,
        "margin_percent": margin_percent,
        # Budget vs réalisé par catégorie (§7.3.7)
        "by_category": _budget_vs_actual_by_category(project),
    })
```

Et **brancher les mêmes valeurs** dans `summary/` (remplacer les `None` des [lignes 909-914](inventory-backend-main/api/views.py#L909-L914) par `cost_labour`, `cost_subcontracting`, `cost_rental`, `cost_total`, `margin_percent`). Factoriser le calcul dans une fonction privée `_compute_project_costs(project)` appelée par les deux endpoints.

---

#### 7.3.7 🆕 Budget prévu vs réalisé + auto-remplissage `actual_amount` matériaux

`ProjectBudgetLine.actual_amount` est nullable et jamais alimenté. On le **calcule automatiquement pour la catégorie `materiaux`** = coût des sorties matières du projet ; les autres catégories restent en saisie manuelle (le réalisé MO/sous-traitance vient des ressources).

```python
def _budget_vs_actual_by_category(project):
    """Renvoie [{category, label, budget, actual, variance, variance_percent}, ...]."""
    Z = Decimal("0")
    completed = StockMovement.objects.filter(
        project=project, status="completed", movement_type="sortie")
    materials_actual = completed.aggregate(t=Coalesce(Sum("total_cost"),
        Value(Z, output_field=DecimalField(max_digits=18, decimal_places=2))))["t"]

    rows = []
    lines = ProjectBudgetLine.objects.filter(project=project)
    # regrouper le budget par catégorie
    from collections import defaultdict
    budget_by_cat, actual_by_cat = defaultdict(lambda: Z), defaultdict(lambda: Z)
    for line in lines:
        budget_by_cat[line.category] += line.budget_amount
        if line.actual_amount is not None:
            actual_by_cat[line.category] += line.actual_amount
    # le réalisé matériaux est dérivé des mouvements (override)
    actual_by_cat["materiaux"] = materials_actual

    for cat, _label in ProjectBudgetLine.CostCategory.choices:
        b, a = budget_by_cat.get(cat, Z), actual_by_cat.get(cat, Z)
        if b == Z and a == Z:
            continue
        variance = b - a
        rows.append({
            "category": cat,
            "budget": str(b),
            "actual": str(a),
            "variance": str(variance),
            "variance_percent": (round(float(a) / float(b) * 100, 1) if b > 0 else None),
            "over_budget": a > b,
        })
    return rows
```

> **Décision :** on **n'écrit pas** `actual_amount` matériaux en base (il se recalcule à chaque sortie, l'écriture serait source d'incohérence). On le **dérive à la lecture**. Si le client veut figer un réalisé matières à une date (clôture), prévoir une action `freeze-actuals/` en post-pilote.

---

#### 7.3.8 🆕 Historique des prix d'achat & écarts fournisseurs

Demandé en Q17 (« historique des prix d'achat », « écarts de coût par fournisseur et par période »). **Dérivable des mouvements `entree`** — pas de nouveau modèle nécessaire.

Endpoint sur `ItemViewSet` :

```python
@action(detail=True, methods=["get"], url_path="price-history")
def price_history(self, request, pk=None):
    item = self.get_object()
    qs = (StockMovement.objects
          .filter(item=item, movement_type="entree",
                  unit_price_at_movement__isnull=False)
          .select_related("item__supplier")
          .order_by("-created_at")
          .values("created_at", "unit_price_at_movement",
                  "quantity", "reference_number"))
    points = [{
        "date": p["created_at"].date().isoformat(),
        "unit_price": str(p["unit_price_at_movement"]),
        "quantity": str(p["quantity"]),
        "reference": p["reference_number"],
    } for p in qs]
    prices = [Decimal(pt["unit_price"]) for pt in points]
    return Response({
        "item_id": str(item.id),
        "current_price": str(item.unit_price) if item.unit_price is not None else None,
        "weighted_average_cost": str(valuation._weighted_average_cost(item)),
        "min_price": str(min(prices)) if prices else None,
        "max_price": str(max(prices)) if prices else None,
        "points": points,
    })
```

> Le CUMP (`weighted_average_cost`) est exposé ici pour que la fiche article affiche, côte à côte, **dernier prix** vs **coût moyen pondéré** — utile pour comprendre l'impact de la méthode choisie.

---

#### 7.3.9 🆕 Inventaire valorisé (rapport valeur du stock)

Demandé en Q19 (« Inventaire valorisé — valeur totale du stock »). Endpoint custom sur `ItemViewSet` ou `StockBalanceViewSet` :

```
GET /api/v1/items/stock-valuation/
```

Renvoie, par article : quantité totale, méthode active, coût unitaire de valorisation, valeur. Valeur selon méthode :

- `last_price` : `total_qty × item.unit_price`
- `wac` / `fifo` : Σ des couches ouvertes `quantity_remaining × unit_cost` (la valeur réelle du registre).

```python
@action(detail=False, methods=["get"], url_path="stock-valuation")
def stock_valuation(self, request):
    method = valuation._active_method()
    rows, grand_total = [], Decimal("0")
    for item in Item.objects.filter(is_active=True).select_related("category"):
        layer_val = StockCostLayer.objects.filter(
            item=item, quantity_remaining__gt=0).aggregate(
            v=Coalesce(Sum(F("quantity_remaining") * F("unit_cost")),
                       Value(Decimal("0"), output_field=DecimalField(max_digits=18, decimal_places=2))))["v"]
        total_qty = StockBalance.objects.filter(item=item).aggregate(
            q=Coalesce(Sum("quantity"), Value(Decimal("0"),
                       output_field=DecimalField(max_digits=18, decimal_places=3))))["q"]
        if method == "last_price":
            value = total_qty * (item.unit_price or Decimal("0"))
        else:
            value = layer_val
        if total_qty <= 0 and value <= 0:
            continue
        grand_total += value
        rows.append({
            "item_id": str(item.id), "name": item.name, "sku": item.sku,
            "category_name": item.category.name if item.category_id else None,
            "total_quantity": str(total_qty), "value": str(value),
        })
    return Response({"method": method, "grand_total": str(grand_total), "items": rows})
```

> Ce rapport sera repris/exporté en Section 9 (PDF/Excel). Ici on fournit l'endpoint JSON ; l'export est hors périmètre Section 7.

---

#### 7.3.10 Multi-devise, TVA, taxes (cadrage pilote)

Q18 demande FCFA/EUR/USD/CNY configurable + TVA + taxes locales + frais transport/douanes.

**Décision pilote (à valider avec le client) :**
- **Mono-devise par déploiement** : `OrganizationSettings.default_currency` (déjà ajouté §7.3.2) + `project.currency` existant. **Pas de conversion temps réel multi-devise** dans le pilote (complexité taux de change quotidiens). Tous les montants d'un chantier sont dans sa devise. Multi-devise avec table de taux = évolution post-pilote.
- **TVA** : `OrganizationSettings.vat_rate_percent` (ajouté §7.3.2). Les coûts sont suivis **HT** ; la TVA est une ligne de calcul affichée (HT → TVA → TTC) dans l'onglet Coûts, jamais stockée par mouvement. Garde le modèle simple.
- **Frais transport / douanes** : traités comme `ProjectBudgetLine` catégorie `logistique` (déjà existante) — pas de champ dédié.

---

#### 7.3.11 Routes & URLs

Rien à enregistrer de nouveau côté router (les `@action` sont auto-routées). Récapitulatif des nouveaux endpoints :

| Endpoint | Méthode | Rôle |
|----------|---------|------|
| `/api/v1/projects/{id}/summary/` | GET | ✏️ enrichi — postes de coût remplis |
| `/api/v1/projects/{id}/cost-breakdown/` | GET | 🆕 détail complet coût + budget vs réalisé + marge |
| `/api/v1/items/{id}/price-history/` | GET | 🆕 historique prix d'achat + CUMP |
| `/api/v1/items/stock-valuation/` | GET | 🆕 inventaire valorisé |

---

### 7.4 Spécifications Frontend

#### 7.4.1 Paramètres — sélecteur de méthode de valorisation (`SettingsPage.tsx`)

Ajouter une carte **« Valorisation du stock »** dans les paramètres organisation :

```
┌─ Valorisation du stock ──────────────────────────────────────┐
│ Méthode de valorisation des sorties                          │
│  ( ) Dernier prix d'achat connu                              │
│      Simple — chaque sortie au dernier prix payé.            │
│  (•) Coût moyen pondéré (CUMP)            [Recommandé]        │
│      Lisse les variations de prix. Standard comptable.       │
│  ( ) FIFO / PEPS                                             │
│      Consomme les plus anciens lots d'abord. Traçabilité fine.│
│                                                              │
│ ⚠️ Le changement s'applique aux prochaines sorties.          │
│    Les coûts déjà figés ne sont pas recalculés.              │
│                                                              │
│ Devise par défaut   [ FCFA ▼ ]    TVA   [ 18 ] %             │
│                                          [ Enregistrer ]     │
└──────────────────────────────────────────────────────────────┘
```

- `PATCH /api/v1/organization-settings/{id}/` avec `{ stock_valuation_method, default_currency, vat_rate_percent }`.
- Visible pour `administrateur` uniquement.
- Type TS : ajouter `stock_valuation_method: 'last_price' | 'wac' | 'fifo'`, `default_currency: string`, `vat_rate_percent: string` à `OrganizationSettings` ([api.ts:530](inventory-client-main/src/types/api.ts#L530)).

#### 7.4.2 Onglet Coûts du projet (`ProjectDetailPage.tsx`)

Renforcer l'onglet Budget existant ou ajouter un onglet **« Coûts »** alimenté par `cost-breakdown/`.

**A. Cartes de synthèse (haut) :**

```
┌ Coût total ─┐ ┌ Budget ─────┐ ┌ Marge ──────┐ ┌ Avancement ─┐
│ 142,3 M FCFA│ │ 185,0 M FCFA│ │ +77,7 M     │ │    65 %     │
│ 77 % budget │ │             │ │ +35,3 %     │ │             │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

- Marge verte si positive, rouge si négative. `—` si `contract_value` absent.

**B. Répartition par poste (donut + liste) :** matériaux, MO, sous-traitance, location, frais généraux, pertes. Chaque poste avec montant + % du total.

**C. Tableau Budget vs Réalisé (depuis `by_category`) :**

```
Poste            Budget        Réalisé       Écart        %
Matériaux        50,0 M        47,2 M        +2,8 M       94%
Main d'œuvre     40,0 M        42,5 M        −2,5 M ⚠️    106%
Sous-traitance   30,0 M        28,0 M        +2,0 M       93%
...
```

- Ligne en rouge + ⚠️ si `over_budget` (réalisé > budget) → déclenchera une alerte en Section 8.
- Réalisé matériaux = badge « auto » (dérivé des mouvements, non éditable).

#### 7.4.3 Fiche article — historique des prix (`ItemDetailPage.tsx`)

Dans la fiche article (connectée en Section 3), ajouter un bloc **« Évolution du prix d'achat »** depuis `price-history/` :

- Mini graphique ligne (réutiliser la lib de charts déjà présente).
- Affichage côte à côte : **Dernier prix** `current_price` · **Coût moyen pondéré** `weighted_average_cost` · **Min / Max** sur la période.
- Tableau des 10 dernières réceptions (date, prix, quantité, n° de bon).

#### 7.4.4 Inventaire valorisé (`InventoryPage.tsx` ou `ReportsPage`)

Bouton **« Inventaire valorisé »** → vue/onglet listant articles × quantité × valeur, avec **total général** et indication de la **méthode active**. Source : `items/stock-valuation/`. Export PDF/Excel renvoyé à la Section 9.

#### 7.4.5 `NewMovementPage.tsx` — comportement du prix selon le type

- Type `entree` : champ **Prix unitaire d'achat** éditable (obligatoire si l'article n'a pas de prix). Alimente `unit_price_at_movement` et met à jour le dernier prix de l'article.
- Type `sortie` / `ajustement` : **masquer ou verrouiller** le champ prix. Afficher à la place : *« Coût calculé automatiquement à la validation (méthode : CUMP) »*. Le récapitulatif de coût total n'est connu qu'après création (le backend le fige).

---

### 7.5 Dépendances

| Dépendance | Impact |
|------------|--------|
| Section 3 (Inventaire) ✅ | `Item.unit_price` = dernier prix ; alimente couches et fallback valorisation. |
| Section 4 (Mouvements) ✅ | `total_cost`, `status=completed`, `_apply_movement_to_balances()`, action `approve/` : points d'insertion de la valorisation. |
| Section 5 (Projets) ⚠️ | `ProjectResource` enrichi (`main_oeuvre` + coûts) **non implémenté** — porté ici en §7.3.1 (prérequis). `summary/` à enrichir. |
| Section 6 (Lieux) ✅ | Les `StockBalance` par emplacement restent la source des quantités ; le coût est au niveau article. |
| Section 8 (Alertes) ⏳ | `over_budget` (§7.3.7) et `margin_percent < 0` déclencheront les alertes « dépassement de budget » (Q27). `auto_alerts_enabled` sur Project existe déjà. |
| Section 9 (Rapports) ⏳ | Exports PDF/Excel de l'inventaire valorisé, du coût chantier et du budget vs réalisé. |

---

### 7.6 Priorité d'implémentation

| Étape | Tâche | Estimation |
|-------|-------|------------|
| 1 | **Backend : migration `0022`** — `ProjectResource` enrichi (`main_oeuvre`, `unit_cost`, `cost_unit`, `planned_duration`) + serializer `estimated_cost` + filtres ViewSet | 0.75 j |
| 2 | **Backend : migration `0023`** — `OrganizationSettings.stock_valuation_method` + `default_currency` + `vat_rate_percent` | 0.25 j |
| 3 | **Backend : migration `0024` + `0025`** — modèle `StockCostLayer` + backfill couches initiales | 0.75 j |
| 4 | **Backend : `api/valuation.py`** — service complet (WAC, FIFO, consommation, ouverture de couches) | 1.5 j |
| 5 | **Backend : intégration dans `_apply_movement_to_balances()`** + `unit_price_at_movement` lecture seule pour sortie/ajustement | 1 j |
| 6 | **Backend : `_compute_project_costs()` + endpoint `cost-breakdown/`** + enrichir `summary/` | 1.5 j |
| 7 | **Backend : budget vs réalisé** (`_budget_vs_actual_by_category`, réalisé matériaux dérivé) | 0.5 j |
| 8 | **Backend : `price-history/` + `stock-valuation/`** | 1 j |
| 9 | **Backend : tests** valorisation (3 méthodes), coût chantier, marge, budget vs réalisé | 1.5 j |
| 10 | **Frontend : `SettingsPage`** — carte valorisation + devise + TVA | 0.75 j |
| 11 | **Frontend : onglet Coûts projet** — cartes synthèse, donut, tableau budget vs réalisé | 2 j |
| 12 | **Frontend : `ItemDetailPage`** — bloc historique prix + CUMP | 1 j |
| 13 | **Frontend : inventaire valorisé** + comportement prix `NewMovementPage` | 1 j |
| 14 | **Frontend : types TS** (`OrganizationSettings`, `ProjectResource`, `CostBreakdown`, `PriceHistory`) | 0.5 j |
| **Total estimé** | | **~15,5 jours** |

> **Chemin critique :** étapes 3 → 4 → 5 (registre + service + intégration). Sans elles, aucune méthode de valorisation n'existe et les coûts chantier restent faux. À traiter en premier.

---

### 7.7 Critères de validation (Definition of Done)

**Valorisation (le cœur) :**
- [ ] `OrganizationSettings.stock_valuation_method` est configurable via l'API (`last_price` / `wac` / `fifo`), défaut `wac`.
- [ ] Méthode `last_price` : une `sortie` est figée à `item.unit_price` courant.
- [ ] Méthode `wac` : 2 entrées (100 @ 1000, puis 100 @ 1400) → une sortie de 50 est valorisée à **1200** (CUMP) ; `total_cost = 60 000`.
- [ ] Méthode `fifo` : mêmes entrées → une sortie de 150 consomme 100 @ 1000 + 50 @ 1400 → coût unitaire **1133,33**, `total_cost = 170 000`.
- [ ] Après une sortie, `quantity_remaining` des couches FIFO est correctement décrémenté quelle que soit la méthode.
- [ ] Un `transfert` ne modifie **aucune** couche de coût.
- [ ] `unit_price_at_movement` envoyé par le client sur une `sortie` est **ignoré** (calculé serveur) ; accepté sur une `entree`.
- [ ] Changer la méthode ne recalcule pas les coûts déjà figés.
- [ ] Une `entree` met à jour `item.unit_price` (dernier prix connu).
- [ ] L'approbation (`approve/`) d'un mouvement `pending` applique la valorisation à l'instant de l'approbation.

**Coût chantier & budget :**
- [ ] `GET /projects/{id}/cost-breakdown/` retourne matériaux, pertes, MO, sous-traitance, location, frais généraux, total, budget, marge.
- [ ] `summary/` ne renvoie plus `None` pour `cost_labour`, `cost_subcontracting`, `cost_rental`, `cost_total`, `margin_percent`.
- [ ] Une `ProjectResource` `main_oeuvre` (8000 FCFA/h × 240 h) contribue **1 920 000** à `cost_labour`.
- [ ] `margin = contract_value − cost_total` ; `margin_percent` correct ; `None` si pas de `contract_value`.
- [ ] `by_category` : le réalisé `materiaux` = Σ `total_cost` des sorties `completed` (dérivé, non stocké).
- [ ] `over_budget=true` quand réalisé > budget d'une catégorie.

**Historique & inventaire valorisé :**
- [ ] `GET /items/{id}/price-history/` retourne les points de prix des entrées + `current_price` + `weighted_average_cost` + min/max.
- [ ] `GET /items/stock-valuation/` retourne valeur par article + total général + méthode active ; valeur cohérente avec la méthode.

**Frontend :**
- [ ] `SettingsPage` permet de choisir la méthode (admin) ; avertissement sur les coûts déjà figés affiché.
- [ ] L'onglet Coûts affiche cartes synthèse, répartition par poste et tableau budget vs réalisé avec écarts en rouge.
- [ ] `ItemDetailPage` affiche l'historique des prix + dernier prix + CUMP côte à côte.
- [ ] `NewMovementPage` verrouille le champ prix sur sortie/ajustement et l'affiche éditable sur entrée.
- [ ] L'inventaire valorisé liste articles + valeurs + total + méthode active.
