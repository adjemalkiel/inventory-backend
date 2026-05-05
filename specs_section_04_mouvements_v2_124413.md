# Rapport de Spécifications — Bâtir Pro
## Section 4 : Mouvements de Stock
### Version 2 — mise à jour post-Section 3 et audit du code

---

### 4.1 Contexte & justification

Les mouvements de stock sont le flux vital de l'application. Le client estime 15 à 40 mouvements par jour, soit 80 à 200 par semaine (Q12). Ils effectuent 5 types de mouvements : réception fournisseur, sortie chantier, transfert inter-sites, retour de chantier, et ajustement/correction (Q11). Ils ajoutent un 6ème cas : l'affectation temporaire d'équipements avec réintégration au stock.

Le processus actuel repose sur des bons papier avec un workflow en 6 étapes : demande → préparation du bon → validation → signature → remise → archivage (Q13). Le client veut digitaliser totalement ce processus avec signature électronique, historique et pièces jointes (Q13).

**Exigence critique :** Des workflows d'approbation configurables sont requis avant toute sortie significative. La validation peut être assurée par le chef de chantier, le conducteur de travaux, le responsable logistique, ou la direction selon le seuil (Q14).

**État actuel du code (après Section 3) :**

| Composant | État | Détail |
|-----------|------|--------|
| `_apply_movement_to_balances()` | ✅ **Résolu en Section 3** | Implémentée dans `api/views.py`, appelée dans `perform_create()`. Utilise `select_for_update()`, transaction atomique, `ValidationError` 400 si stock insuffisant. |
| `StockMovementFilter` | ✅ Existe | Filtre `date_from/to`, `created_at_after/before`, `movement_type`, `created_by`. |
| Pagination | ✅ `BatirPageNumberPagination` | Configurée globalement, `page_size=25`, `max_page_size=500`. |
| `StockMovementViewSet` | ⚠️ Partiel | `filter_backends`, `filterset_class`, `ordering_fields` présents. Manque `SearchFilter`, `search_fields`, et filtres sur `status`, `item`, `project`, lieux. |
| Types de mouvement | ⚠️ Incomplet | 4 types (`entree`, `sortie`, `transfert`, `retour`). Manque `ajustement`. |
| Champs `StockMovement` | ❌ Manquants | `status`, `unit_price_at_movement`, `total_cost`, `reference_number`, `approved_by`, `approved_at`, `rejection_reason`, `attachment`, `signature`, `loss_reason`. |
| Validations métier serializer | ❌ Manquantes | Source/destination requises, source ≠ destination, projet requis pour sortie. |
| Workflow d'approbation | ❌ Manquant | Modèle `ApprovalRule`, endpoints `approve/`, `reject/`. |
| Numéro de référence auto | ❌ Manquant | Auto-génération `BS-2026-04-0001`. |

> **Note :** Le RBAC d'accès aux mouvements est déjà en place dans `api/access.py` (`StockMovementAccess`). Le rôle `conducteur_travaux` dispose de la permission `movement.validate`. Les scopes magasinier et chef de chantier sont filtrés. Il n'est pas nécessaire de recréer ces garde-fous.

---

### 4.2 Types de mouvements

Sur la base de Q11 et Q14, voici la taxonomie complète :

| Type | Code backend | Effet sur StockBalance | Validation requise |
|------|-------------|----------------------|-------------------|
| **Réception fournisseur** | `entree` | +quantité sur le lieu destination | Non (magasinier confirme) |
| **Sortie vers chantier** | `sortie` | -quantité sur le lieu source | **OUI** — workflow d'approbation |
| **Transfert inter-sites** | `transfert` | -quantité source, +quantité destination | OUI si seuil dépassé |
| **Retour de chantier** | `retour` | +quantité sur le lieu destination | Non (magasinier confirme) |
| **Ajustement (perte/casse)** | `ajustement` | delta sur le lieu source ou destination | OUI si négatif — motif obligatoire |

**Action backend :** Ajouter `ajustement` aux choix de `MovementType` dans `api/models.py` :

```python
class MovementType(models.TextChoices):
    ENTREE = "entree", "Entrée (Réception Fournisseur)"
    SORTIE = "sortie", "Sortie (Usage Chantier)"
    TRANSFERT = "transfert", "Transfert Inter-Sites"
    RETOUR = "retour", "Retour de Chantier"
    AJUSTEMENT = "ajustement", "Ajustement / Correction"
```

> **Convention de signe pour `ajustement` :** Le champ `quantity` sur le mouvement est **toujours stocké comme valeur absolue positive**. Le sens (perte ou surplus) est déterminé par la présence de `source_storage_location` (décrément) ou `destination_storage_location` (incrément). Cette convention est cohérente avec les 4 types existants et évite d'avoir des quantités négatives en base, ce qui casserait la validation existante dans `_apply_movement_to_balances()`.

---

### 4.3 Spécifications Backend

#### 4.3.1 Modifications du modèle `StockMovement`

Champs à **ajouter** (nouvelle migration) :

| Champ | Type Django | Description | Null/Blank |
|-------|-------------|-------------|-----------|
| `status` | `CharField(32, choices=MovementStatus)` | Statut du workflow | Non — défaut `draft` |
| `unit_price_at_movement` | `DecimalField(14, 2)` | Prix unitaire figé au moment du mouvement | `null=True, blank=True` |
| `total_cost` | `DecimalField(16, 2)` | `quantity × unit_price_at_movement` — calculé auto | `null=True, blank=True` |
| `reference_number` | `CharField(64, blank=True)` | Numéro de bon auto-généré | `blank=True` |
| `approved_by` | `FK → User, null=True` | Utilisateur valideur | `null=True, blank=True` |
| `approved_at` | `DateTimeField, null=True` | Date/heure de validation | `null=True, blank=True` |
| `rejection_reason` | `TextField(blank=True)` | Motif de refus | `blank=True` |
| `attachment` | `FileField(null=True, blank=True, upload_to='movements/%Y/%m/')` | Photo du bon, de la livraison | `null=True, blank=True` |
| `loss_reason` | `CharField(32, choices=LossReason, blank=True)` | Motif d'ajustement négatif | `blank=True` |

Choices pour `status` :

```python
class MovementStatus(models.TextChoices):
    DRAFT = "draft", "Brouillon"
    PENDING = "pending", "En attente de validation"
    APPROVED = "approved", "Validé"
    REJECTED = "rejected", "Rejeté"
    COMPLETED = "completed", "Exécuté"
```

Choices pour `loss_reason` :

```python
class LossReason(models.TextChoices):
    PERTE = "perte", "Perte"
    CASSE = "casse", "Casse / Détérioration"
    VOL = "vol", "Vol"
    PEREMPTION = "peremption", "Péremption"
    AUTRE = "autre", "Autre"
```

> **`total_cost` :** Ne pas calculer côté frontend. Le calculer automatiquement dans `StockMovementSerializer.validate()` : `total_cost = quantity × unit_price_at_movement` si les deux sont présents, sinon `None`. Ce champ est en lecture seule dans le serializer.

---

#### 4.3.2 ⚡ Extension de `_apply_movement_to_balances()` et intégration du workflow

> **⚠️ Ne pas réécrire `_apply_movement_to_balances()`.** La fonction existe dans `api/views.py`, utilise `select_for_update()`, des transactions atomiques, et lève `ValidationError` si le stock est insuffisant. Elle est plus robuste que l'exemple de la v1 (qui n'avait ni `select_for_update`, ni transaction, ni gestion de `zone_label`). Travailler à partir de l'existant.

**Deux modifications seulement :**

**1. Étendre la fonction pour le type `ajustement`**

Ajouter le cas `ajustement` à la fin de la fonction existante :

```python
def _apply_movement_to_balances(movement: StockMovement) -> None:
    # ... code existant pour entree / sortie / transfert / retour ...

    # CAS AJUSTEMENT — ajouter après les cas existants
    elif movement.movement_type == 'ajustement':
        # Convention : source_storage_location = décrément (perte/casse)
        #              destination_storage_location = incrément (surplus retrouvé)
        # quantity est toujours positif (valeur absolue)
        loc = movement.source_storage_location or movement.destination_storage_location
        if loc is None:
            raise ValidationError(
                {"source_storage_location": "Un emplacement est requis pour un ajustement."}
            )
        balance, _ = StockBalance.objects.select_for_update().get_or_create(
            item=movement.item,
            storage_location=loc,
            zone_label='',
            defaults={
                'quantity': 0,
                'updated_by': movement.updated_by or movement.created_by,
                'created_by': movement.updated_by or movement.created_by,
            },
        )
        if movement.source_storage_location:
            # Décrément (perte, casse, vol) — vérifier le stock disponible
            if balance.quantity < movement.quantity:
                raise ValidationError({
                    "quantity": (
                        f"Stock insuffisant dans « {loc.name} » : "
                        f"disponible {balance.quantity}, ajustement demandé {movement.quantity}."
                    )
                })
            balance.quantity -= movement.quantity
        else:
            # Incrément (surplus retrouvé)
            balance.quantity += movement.quantity
        audit_user = movement.updated_by or movement.created_by
        balance.updated_by = audit_user
        balance.save(update_fields=['quantity', 'updated_at', 'updated_by'])
```

**2. Adapter `perform_create` pour le workflow de statut**

Remplacer `perform_create` dans `StockMovementViewSet` pour conditionner l'application des balances au statut :

```python
def perform_create(self, serializer):
    user = self.request.user if self.request.user.is_authenticated else None
    with transaction.atomic():
        movement = serializer.save(created_by=user, updated_by=user)
        # Appliquer les balances uniquement si le mouvement est immédiatement exécuté.
        # Les mouvements en statut 'pending' attendent l'approbation via /approve/.
        if movement.status == 'completed':
            _apply_movement_to_balances(movement)
```

> Les mouvements sans règle d'approbation applicable seront créés avec `status=completed` directement par le serializer (voir §4.3.4). Les autres seront créés avec `status=pending` et les balances ne bougent pas jusqu'à l'approbation.

---

#### 4.3.3 Validations métier

Ajouter dans `StockMovementSerializer.validate()`. **Note :** le contrôle du stock disponible est déjà géré par `_apply_movement_to_balances()` (level base de données, avec `select_for_update`). Les règles ci-dessous sont des **pre-flight checks au niveau serializer** — plus lisibles pour le client API, et sans coût de requête DB pour les erreurs simples.

| Règle | Condition | Champ d'erreur |
|-------|-----------|----------------|
| Quantité strictement positive | `quantity <= 0` | `quantity` |
| Source requise pour sortie/transfert | `movement_type in (sortie, transfert) and not source` | `source_storage_location` |
| Destination requise pour entrée/retour/transfert | `movement_type in (entree, retour, transfert) and not destination` | `destination_storage_location` |
| Source ≠ destination pour transfert | `source == destination` | `destination_storage_location` |
| Projet requis pour sortie chantier | `movement_type == sortie and not project` | `project` |
| Motif requis pour ajustement perte | `movement_type == ajustement and source and not loss_reason` | `loss_reason` |
| Au moins un emplacement pour ajustement | `movement_type == ajustement and not source and not destination` | `source_storage_location` |

Calcul automatique de `total_cost` dans `validate()` :
```python
qty = data.get('quantity')
price = data.get('unit_price_at_movement')
if qty and price:
    data['total_cost'] = qty * price
```

---

#### 4.3.4 Workflow d'approbation

Le client exige des workflows configurables (Q14). Implémenter un système simple mais extensible.

**Modèle `ApprovalRule` (à créer) :**

```python
class ApprovalRule(AuditedModel):
    """Règle déclenchant une approbation avant exécution du mouvement."""
    movement_type = models.CharField(max_length=16, choices=StockMovement.MovementType.choices)
    min_value_threshold = models.DecimalField(max_digits=16, decimal_places=2, default=0)
    approver_role = models.ForeignKey('Role', on_delete=models.CASCADE, related_name='approval_rules')
    project = models.ForeignKey('Project', null=True, blank=True, on_delete=models.SET_NULL)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['movement_type', 'min_value_threshold']

    def __str__(self):
        return f"Règle {self.movement_type} ≥ {self.min_value_threshold}"
```

**Logique d'approbation dans `StockMovementSerializer.create()` (ou `perform_create`) :**

1. Quand un mouvement de type `sortie` ou `transfert` est soumis, vérifier les `ApprovalRule` actives.
2. Si une règle match (`movement_type` correspondant ET `total_cost >= min_value_threshold`), créer avec `status=pending`.
3. Si aucune règle ne match → `status=completed` → `_apply_movement_to_balances()` est appelée immédiatement.

```python
def _determine_initial_status(movement_data: dict) -> str:
    """Retourne 'pending' si une ApprobationRule s'applique, sinon 'completed'."""
    mtype = movement_data.get('movement_type')
    total = movement_data.get('total_cost') or 0
    if mtype not in ('sortie', 'transfert', 'ajustement'):
        return 'completed'
    rules = ApprovalRule.objects.filter(
        movement_type=mtype,
        is_active=True,
        min_value_threshold__lte=total,
    )
    return 'pending' if rules.exists() else 'completed'
```

**Endpoints d'action sur les mouvements :**

| Endpoint | Méthode | Description | Permission |
|----------|---------|-------------|------------|
| `/api/v1/stock-movements/{id}/approve/` | POST | Approuve → `status=completed`, applique les balances | `movement.validate` (conducteur_travaux) |
| `/api/v1/stock-movements/{id}/reject/` | POST | Rejette avec motif → `status=rejected`, stock inchangé | `movement.validate` |
| `/api/v1/stock-movements/?status=pending` | GET | Liste des mouvements en attente | Rôle approbateur — filtré par RBAC existant |

> **Note :** Ne pas créer un endpoint `/pending/` séparé. Le filtre `?status=pending` via le `filterset_fields` étendu (§4.3.6) suffit et est cohérent avec l'API existante. Le badge frontend (§4.4.4) utilisera ce même filtre.

Implémentation des actions `@action` :

```python
@action(detail=True, methods=['post'], url_path='approve',
        permission_classes=[IsAuthenticated])
def approve(self, request, pk=None):
    movement = self.get_object()
    if not rbac.user_has_permission(request.user, 'movement.validate'):
        return Response({'detail': 'Permission refusée.'}, status=403)
    if movement.status != 'pending':
        return Response({'detail': f"Ce mouvement est en statut « {movement.status} » et ne peut pas être approuvé."}, status=400)
    with transaction.atomic():
        _apply_movement_to_balances(movement)
        movement.status = 'completed'
        movement.approved_by = request.user
        movement.approved_at = timezone.now()
        movement.updated_by = request.user
        movement.save(update_fields=['status', 'approved_by', 'approved_at', 'updated_by', 'updated_at'])
    return Response(StockMovementSerializer(movement).data)


@action(detail=True, methods=['post'], url_path='reject',
        permission_classes=[IsAuthenticated])
def reject(self, request, pk=None):
    movement = self.get_object()
    if not rbac.user_has_permission(request.user, 'movement.validate'):
        return Response({'detail': 'Permission refusée.'}, status=403)
    if movement.status != 'pending':
        return Response({'detail': f"Ce mouvement est en statut « {movement.status} » et ne peut pas être rejeté."}, status=400)
    reason = (request.data.get('rejection_reason') or '').strip()
    if not reason:
        return Response({'detail': 'Un motif de refus est requis.'}, status=400)
    movement.status = 'rejected'
    movement.rejection_reason = reason
    movement.approved_by = request.user
    movement.approved_at = timezone.now()
    movement.updated_by = request.user
    movement.save(update_fields=['status', 'rejection_reason', 'approved_by', 'approved_at', 'updated_by', 'updated_at'])
    return Response(StockMovementSerializer(movement).data)
```

---

#### 4.3.5 Génération automatique du numéro de référence

Le champ `reference_number` est auto-généré dans `StockMovementSerializer.create()` ou dans `perform_create`. Format :

```
{TYPE_PREFIX}-{ANNÉE}-{MOIS}-{SÉQUENTIEL sur 4 chiffres}
```

Exemples : `BS-2026-04-0001` (bon de sortie), `BE-2026-04-0042` (bon d'entrée), `BT-2026-04-0015` (bon de transfert), `BR-2026-04-0003` (bon de retour), `BA-2026-04-0007` (bon d'ajustement).

```python
TYPE_PREFIX = {
    'entree': 'BE',
    'sortie': 'BS',
    'transfert': 'BT',
    'retour': 'BR',
    'ajustement': 'BA',
}

def _generate_reference_number(movement_type: str) -> str:
    from django.utils import timezone
    prefix = TYPE_PREFIX.get(movement_type, 'BX')
    now = timezone.now()
    year, month = now.year, now.month
    # Compteur mensuel : nombre de mouvements du même type ce mois
    count = StockMovement.objects.filter(
        movement_type=movement_type,
        created_at__year=year,
        created_at__month=month,
    ).count() + 1
    return f"{prefix}-{year}-{month:02d}-{count:04d}"
```

> Générer le `reference_number` dans `perform_create` après `serializer.save()`, et le sauvegarder avec `update_fields=['reference_number']`. Cela évite une race condition sur le compteur : le mouvement est déjà en base quand on compte, le compteur est donc toujours ≥ 1.

---

#### 4.3.6 Filtrage et pagination sur `StockMovementViewSet`

> **État actuel :** `StockMovementFilter` existe dans `api/filters.py` avec `date_from`, `date_to`, `created_at_after`, `created_at_before`, `movement_type`, `created_by`. `StockMovementViewSet` a déjà `filter_backends = [DjangoFilterBackend, OrderingFilter]`, `filterset_class = StockMovementFilter`, `ordering_fields = ['created_at', 'quantity']`, `ordering = ['-created_at']`.

**À ajouter/modifier :**

**1. Étendre `StockMovementFilter` dans `api/filters.py` :**

```python
class StockMovementFilter(django_filters.FilterSet):
    # Champs déjà présents :
    date_from = django_filters.DateFilter(field_name='created_at', lookup_expr='date__gte')
    date_to = django_filters.DateFilter(field_name='created_at', lookup_expr='date__lte')
    created_at_after = django_filters.IsoDateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_at_before = django_filters.IsoDateTimeFilter(field_name='created_at', lookup_expr='lte')

    class Meta:
        model = StockMovement
        fields = [
            # Existants :
            'movement_type', 'created_by',
            # À ajouter :
            'status', 'item', 'project',
            'source_storage_location', 'destination_storage_location',
        ]
```

**2. Ajouter `SearchFilter` et `search_fields` dans `StockMovementViewSet` :**

```python
class StockMovementViewSet(SetAuditUsersMixin, viewsets.ModelViewSet):
    # Ajouter SearchFilter aux backends existants :
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = StockMovementFilter
    search_fields = ['reference_number', 'item__name', 'item__sku', 'comment']
    ordering_fields = ['created_at', 'quantity', 'total_cost']  # ajouter total_cost
    ordering = ['-created_at']
    # ... reste inchangé
```

---

### 4.4 Spécifications Frontend

#### 4.4.1 Page Liste des Mouvements (`/movements`) — `MovementsPage.tsx`

**État actuel :** 100% hardcodé (4 lignes statiques, filtres décoratifs, graphique factice, KPIs en dur).

**Modifications :**

**A. Tableau principal :**
- Fetch `GET /api/v1/stock-movements/?ordering=-created_at&page=1`
- Colonnes : Date, Référence, Type, Article, Quantité, Source → Destination, Chantier, Statut, Utilisateur
- Badge de statut coloré : `completed` vert, `pending` orange, `rejected` rouge, `draft` gris
- Clic sur une ligne → `/movements/:id`

**B. Onglets de type :**
Les 6 onglets existent déjà. Connecter au paramètre `?movement_type=entree|sortie|transfert|retour|ajustement`.

**C. Filtres :**
- **Période** : `?created_at_after=...&created_at_before=...`
- **Utilisateur** : dropdown depuis API users → `?created_by={id}`
- **Statut** : dropdown → `?status=pending|completed|rejected`
- **Bouton Réinitialiser** : vider tous les filtres

**D. KPI "Mouvements 24h" :**
`/api/v1/dashboard/summary/` → champ `movements_today`.

**E. Graphique "Activité de la semaine" :**
Fetch `GET /api/v1/stock-movements/?created_at_after={7_jours_avant}&ordering=created_at`, agréger par jour côté frontend (utiliser `date-fns` ou `dayjs` déjà présent). Pas d'endpoint dédié nécessaire — le volume (≤ 280 mouvements sur 7 jours à 40/jour) reste raisonnable pour un fetch unique.

**F. Pagination :**
Même pattern que `InventoryPage` (déjà implémenté en Section 3) : `page` state, `total` depuis `data.count`, affichage "X-Y sur {total}".

---

#### 4.4.2 Page Nouveau Mouvement (`/inventory/new-movement`) — `NewMovementPage.tsx`

**État actuel :** Connectée à l'API, fonctionnelle. C'est la page la mieux intégrée.

**Ajouts nécessaires :**

| Ajout | Détail |
|-------|--------|
| **Prix unitaire** | Pré-remplir depuis `item.unit_price` (chargé en Section 3), modifiable. Stocker dans `unit_price_at_movement`. |
| **Coût total calculé** | Afficher dynamiquement `quantity × unit_price_at_movement` dans le récapitulatif. Lecture seule. |
| **Type "Ajustement"** | Ajouter l'option dans le dropdown. Afficher un champ "Motif" (`loss_reason`) si sélectionné ET si `source_storage_location` est renseigné. |
| **Pièce jointe** | Upload fichier → champ `attachment`. Même pattern que `upload-image` sur Item (Section 3). |
| **Message workflow** | Si `ApprovalRule` applicable (API à créer : `GET /api/v1/approval-rules/?movement_type=sortie&total_cost=X`), afficher : "Ce mouvement nécessitera une validation par [rôle]." |
| **Récapitulatif latéral** | Remplacer les données hardcodées par le stock réel de l'article sélectionné depuis `item.detail.balances`. |

**Supprimer :**
- Le bandeau "Suggestion IA" hardcodé
- Le bloc "Conseil d'expert" statique

---

#### 4.4.3 Page Détail d'un Mouvement — `/movements/:id` (à créer)

Route et composant à créer. Contenu :

- Numéro de référence (badge prominent)
- Type + statut (badge coloré — même palette que MovementsPage)
- Article concerné (lien vers `/inventory/:id`)
- Quantité · Prix unitaire · Coût total
- Lieu source → Lieu destination (flèche visuelle)
- Chantier associé
- Créé par + date de création
- Approuvé/rejeté par + date (si applicable) + motif de refus
- Commentaire
- Pièce jointe / photo (si disponible)

**Actions disponibles :**

| Condition | Actions |
|-----------|---------|
| `status=pending` + rôle `movement.validate` | Boutons **Approuver** / **Rejeter** (avec champ motif sur refus) |
| `status=completed` | Bouton **Imprimer le bon** (PDF — Section 9) |
| Tous statuts | Bouton **Dupliquer** (pré-remplit `/inventory/new-movement` avec les données du mouvement) |

---

#### 4.4.4 Badge mouvements en attente (Sidebar)

Pour les utilisateurs avec la permission `movement.validate` :
- Fetch `GET /api/v1/stock-movements/?status=pending` (utiliser le filtre existant — ne pas créer d'endpoint dédié)
- Afficher `data.count` en badge rouge sur l'icône Mouvements si > 0
- Refetch toutes les 60 secondes (polling simple — pas de WebSocket pour le pilote)

---

### 4.5 Génération de bon (PDF)

Le client veut digitaliser les bons de sortie/livraison (Q13). Pour chaque mouvement `completed`, permettre la génération d'un PDF contenant :

- Numéro de référence, date/heure, type de mouvement
- Article (nom, réf, catégorie, unité)
- Quantité · Prix unitaire · Coût total
- Lieu source et destination
- Chantier associé
- Créé par + Approuvé par
- Commentaire + pièce jointe (si disponible)

**Endpoint :** `GET /api/v1/stock-movements/{id}/pdf/`

Ce point est détaillé en Section 9 (Rapports & Exports). Hors périmètre Section 4 — ne pas bloquer sur ce point.

---

### 4.6 Dépendances

| Dépendance | Impact |
|------------|--------|
| Section 1 (Auth) ✅ | RBAC complet : `StockMovementAccess` dans `access.py`, permission `movement.validate` pour le conducteur. |
| Section 3 (Inventaire) ✅ | `_apply_movement_to_balances()` implémentée. `unit_price` sur Item disponible pour `unit_price_at_movement`. |
| Section 7 (Coûts) ⏳ | `total_cost` sur chaque mouvement alimente le calcul de coût par chantier. |
| Section 9 (Rapports) ⏳ | Génération PDF des bons de sortie. |

---

### 4.7 Priorité d'implémentation

| Étape | Tâche | Estimation | Note |
|-------|-------|------------|------|
| 1 | **Backend : migration** — nouveaux champs `StockMovement` (`status`, `unit_price_at_movement`, `total_cost`, `reference_number`, `approved_by`, `approved_at`, `rejection_reason`, `attachment`, `loss_reason`) | 1 jour | |
| 2 | **Backend : type `ajustement`** — ajouter au `MovementType` + étendre `_apply_movement_to_balances()` | 0.5 jour | Extension de l'existant — ne pas réécrire |
| 3 | **Backend : validations métier** dans `StockMovementSerializer.validate()` | 0.5 jour | |
| 4 | **Backend : `perform_create` conditionnel** — n'applique les balances que si `status=completed` | 0.5 jour | |
| 5 | **Backend : `reference_number` auto-généré** dans `perform_create` | 0.5 jour | |
| 6 | **Backend : modèle `ApprovalRule` + migration + ViewSet + logique** | 1.5 jours | |
| 7 | **Backend : `@action` `approve/` et `reject/`** | 0.5 jour | Permissions RBAC déjà en place |
| 8 | **Backend : étendre `StockMovementFilter`** + ajouter `SearchFilter` et `search_fields` au ViewSet | 0.25 jour | Partiel déjà fait |
| 9 | **Frontend : connecter `MovementsPage`** (tableau, onglets, filtres, pagination, KPI) | 2 jours | |
| 10 | **Frontend : `NewMovementPage`** — prix, coût total, ajustement + motif, pièce jointe, récapitulatif réel | 1 jour | |
| 11 | **Frontend : page détail `/movements/:id`** + actions approve/reject | 1.5 jours | |
| 12 | **Frontend : badge mouvements en attente** dans Sidebar | 0.25 jour | |
| **Total estimé** | | **~10 jours** | (vs. 12 jours v1 — gain grâce aux bases Section 3) |

---

### 4.8 Critères de validation (Definition of Done)

**Backend :**
- [x] Un mouvement `entree` incrémente le `StockBalance` du lieu destination *(résolu Section 3)*
- [x] Un mouvement `sortie` décrémente le `StockBalance` du lieu source *(résolu Section 3)*
- [x] Un mouvement `transfert` décrémente la source ET incrémente la destination *(résolu Section 3)*
- [x] Une sortie est refusée (400) si le stock disponible est insuffisant *(résolu Section 3)*
- [ ] Un ajustement négatif décrémente le stock du lieu source
- [ ] Un ajustement positif incrémente le stock du lieu destination
- [ ] Un ajustement négatif sans `loss_reason` retourne 400
- [ ] Une sortie sans `project` retourne 400
- [ ] Un transfert avec `source == destination` retourne 400
- [ ] Un numéro de référence unique est auto-généré pour chaque mouvement
- [ ] Un mouvement `sortie` au-dessus du seuil d'une `ApprovalRule` est créé en `status=pending`
- [ ] Un mouvement `pending` n'affecte pas le stock à la création
- [ ] Un approbateur (`movement.validate`) peut approuver → `status=completed`, balances appliquées
- [ ] Un approbateur peut rejeter avec motif → `status=rejected`, stock inchangé
- [ ] `GET /api/v1/stock-movements/?status=pending` retourne les mouvements en attente
- [ ] `GET /api/v1/stock-movements/?search=ciment` filtre par nom article
- [ ] `GET /api/v1/stock-movements/?movement_type=sortie&status=pending` combinaison de filtres

**Frontend :**
- [ ] `MovementsPage` n'affiche plus aucune donnée hardcodée
- [ ] Les onglets type et les filtres période/statut/utilisateur sont fonctionnels
- [ ] Le badge mouvements en attente s'affiche dans la Sidebar pour les approbateurs
- [ ] `NewMovementPage` envoie `unit_price_at_movement` et affiche le coût total calculé
- [ ] L'option "Ajustement" est disponible avec le champ motif conditionnel
- [ ] La page `/movements/:id` affiche toutes les informations et les boutons d'action contextuels
