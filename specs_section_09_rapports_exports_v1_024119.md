# Rapport de Spécifications — Bâtir Pro
## Section 9 : Rapports & Exports
### Version 1 — rédigée après audit du code (Sections 1 à 8 implémentées)

---

> **Criticité : HAUTE.** Les rapports sont le canal de sortie de toute la donnée accumulée en Sections 3 à 8. Sans eux, la direction n'a pas de visibilité consolidée et ne peut pas piloter. Demandés en Q19–Q22 avec une liste explicite de 11 types de rapports, 5 formats d'export et 4 fréquences. Le client cite les « tableaux de bord temps réel » et « reporting fiable pour la direction et la finance » comme attentes critiques (Q30/Q32).

> **Périmètre de cette section :**
> - Page centrale `ReportsPage.tsx` — hub de génération de rapports
> - **8 rapports métier** avec sources de données, colonnes et paramètres
> - **Export Excel** (serveur, `openpyxl`) pour les rapports financiers
> - **Export CSV** (client, natif) pour les données brutes
> - **Impression** (`@media print` + `window.print()`) pour tous les rapports
> - **Envoi par email** d'un rapport Excel en pièce jointe (manuel, à la demande)
> - 2 nouveaux endpoints d'agrégation (`monthly-consumption/`, `supplier-performance/`)
> - Implémentation du `dashboard_cost_overview()` (actuellement 501)
> - Enforcement des permissions RBAC rapport déjà définies
> - **Hors périmètre pilote :** rapports automatiques planifiés (Celery), export API/BI, rapports sur-mesure configurables par l'utilisateur

---

### 9.1 Contexte & justification

#### Ce que le client demande (Q19–Q22)

**Rapports souhaités (Q19) :**

| # | Rapport | Fréquence (Q21) | Destinataires (Q22) |
|---|---------|-----------------|---------------------|
| R1 | État des stocks / Inventaire valorisé | Quotidien | Magasinier, direction |
| R2 | Coût total matériaux par chantier | Hebdomadaire | Chef chantier, comptable |
| R3 | Historique des mouvements par période | Quotidien | Magasinier, chef chantier |
| R4 | Articles en stock critique / rupture | Quotidien | Magasinier, achats |
| R5 | Comparaison budget prévu vs réalisé | Hebdomadaire | Direction, comptable |
| R6 | Consommation mensuelle par catégorie | Mensuel | Direction, comptable |
| R7 | Transferts inter-sites | À la demande | Logistique, direction |
| R8 | Performance fournisseurs | Mensuel | Achats, direction |

**Formats demandés (Q20) :** PDF ✦ Excel (.xlsx) ✦ CSV ✦ Impression directe ✦ Email automatique.

#### État actuel du code (après audit)

| Composant | État | Détail |
|-----------|------|--------|
| `requirements.txt` | ❌ Incomplet | Aucune lib PDF/Excel. Python `csv` disponible (built-in). |
| `mail.py` | ⚠️ Partiel | Envoie HTML sans pièce jointe. Pas de `.attach()`. |
| `dashboard_cost_overview()` | ❌ 501 | Endpoint enregistré mais retourne `HTTP 501 Not Implemented`. |
| `GET /items/stock-valuation/` | ✅ JSON | Données prêtes. Pas d'export fichier. ([views.py:895](inventory-backend-main/api/views.py#L895)) |
| `GET /projects/{id}/cost-breakdown/` | ✅ JSON | Données prêtes. Pas d'export fichier. ([views.py:1145](inventory-backend-main/api/views.py#L1145)) |
| `GET /stock-movements/` | ✅ JSON | Filtrable. Export CSV partiel côté client (page courante seulement). |
| Permissions rapport RBAC | ✅ Définies | `reports.financial`, `reports.cost`, `reports.budget`, `reports.site` dans `rbac.py`. **Non enforced.** |
| `ReportsPage.tsx` | ❌ Absent | Aucune page dédiée. Pas de route `/reports`. |
| `InventoryPage.tsx` export | ⚠️ Placeholder | Bouton "Exporter" sans handler. ([InventoryPage.tsx:277](inventory-client-main/src/pages/InventoryPage.tsx#L277)) |
| Bibliothèque de charts | ❌ Absente | Aucun recharts, chart.js, etc. dans `package.json`. |
| CSS `@media print` | ❌ Absent | Aucune règle d'impression dans `index.css`. |

**Conclusion :** toute la donnée nécessaire est agrégée et accessible (Sections 3–8). Section 9 ajoute **(1)** la couche de génération de fichiers (Excel backend, CSV frontend), **(2)** deux nouveaux endpoints d'agrégation, **(3)** la page centrale et les points d'entrée UX, **(4)** l'envoi par email avec pièce jointe.

---

### 9.2 Architecture technique — choix pour le pilote

#### Formats et qui les génère

| Format | Générateur | Justification |
|--------|-----------|---------------|
| **Excel (.xlsx)** | **Serveur** (`openpyxl`) | Nécessaire pour l'envoi email, styling, formules. Seule option fiable sur mobile. |
| **CSV** | **Client** (Blob natif) | Léger, sans dépendance. Extension du pattern déjà en place dans `MovementsPage`. |
| **Impression / PDF** | **Client** (`window.print()` + CSS `@media print`) | Zéro dépendance, qualité suffisante pour les impressions simples. PDF via "Imprimer → Enregistrer en PDF" du navigateur. |
| **Email** | **Serveur** | Génère l'Excel + envoie via `mail.py` enrichi. |

#### Nouvelle dépendance backend

Ajouter à `requirements.txt` :
```
openpyxl>=3.1
```

#### Module `api/exports.py` (nouveau fichier)

Centralise tous les générateurs Excel. Appelé depuis les `@action` des ViewSets. Ne contient pas de logique métier (les données sont reçues en paramètre, déjà calculées).

#### Paradigme des endpoints d'export

Les exports sont des **actions supplémentaires** sur les ViewSets existants. Le dev **n'ajoute pas de nouveaux ViewSets** pour les exports simples — seulement pour les deux nouvelles agrégations.

```
GET /api/v1/items/stock-valuation/export/          → ItemViewSet (nouvelle action)
GET /api/v1/projects/{id}/cost-breakdown/export/   → ProjectViewSet (nouvelle action)
GET /api/v1/stock-movements/export/                → StockMovementViewSet (nouvelle action)
GET /api/v1/items/critical-stock/export/           → ItemViewSet (nouvelle action)
GET /api/v1/reports/monthly-consumption/           → ReportViewSet (nouveau)
GET /api/v1/reports/supplier-performance/          → ReportViewSet (nouveau)
POST /api/v1/reports/send-by-email/                → ReportViewSet (nouveau)
```

---

### 9.3 Catalogue des 8 rapports

#### R1 — Inventaire valorisé

**Source :** `GET /api/v1/items/stock-valuation/` (existant)
**Paramètres :** aucun (méthode de valorisation issue de `OrganizationSettings`)
**Colonnes Excel :**

| Colonne | Source |
|---------|--------|
| Nom de l'article | `item.name` |
| SKU | `item.sku` |
| Catégorie | `item.category_name` |
| Quantité en stock | `item.total_quantity` |
| Coût unitaire | `item.unit_cost` |
| Valeur totale | `item.value` |

**Ligne de total :** "TOTAL" + `grand_total`  
**En-tête :** Méthode active + date de génération  
**Permission :** `reports.financial`

---

#### R2 — Coût chantier complet

**Source :** `GET /api/v1/projects/{id}/cost-breakdown/` (existant)  
**Paramètre :** `project_id` (sélecteur)  
**Colonnes Excel — feuille 1 "Synthèse" :**

| Colonne | Source |
|---------|--------|
| Poste de coût | label (Matériaux, MO, etc.) |
| Coût réalisé | `cost_materials`, `cost_labour`, etc. |
| Budget | issu de `budget_total` ventilé |
| Écart | réalisé − budget |
| % | écart / budget × 100 |

**Feuille 2 "Budget vs Réalisé" :** tableau `by_category` (category, budget, actual, variance, variance_percent, over_budget)  
**Permission :** `reports.cost`

---

#### R3 — Historique des mouvements

**Source :** `GET /api/v1/stock-movements/` (filtré)  
**Paramètres :** `date_from`, `date_to`, `movement_type` (optionnel), `project` (optionnel), `storage_location` (optionnel)  
**Colonnes CSV/Excel :**

| Colonne | Source |
|---------|--------|
| Date | `created_at` (DD/MM/YYYY) |
| Heure | `created_at` (HH:MM) |
| Référence | `reference_number` |
| Type | `movement_type` (libellé) |
| Article | `item.name` |
| SKU | `item.sku` |
| Quantité | `quantity` |
| Unité | `item.unit` |
| Coût unitaire | `unit_price_at_movement` |
| Coût total | `total_cost` |
| Source | `source_storage_location.name` |
| Destination | `destination_storage_location.name` |
| Chantier | `project.name` |
| Statut | `status` (libellé) |
| Créé par | `created_by.full_name` |

**Limite :** sans limite côté backend (l'endpoint existant est paginé — l'action export fait une requête sans pagination). Ajouter un plafond de 10 000 lignes.  
**Permission :** tous les rôles authentifiés

---

#### R4 — Articles en stock critique / rupture

**Source :** `GET /api/v1/items/?stock_status__in=low,stockout&is_active=true`  
**Paramètres :** aucun (snapshot du moment)  
**Colonnes CSV :**

| Colonne | Source |
|---------|--------|
| Nom | `item.name` |
| SKU | `item.sku` |
| Catégorie | `item.category.name` |
| Fournisseur | `item.supplier_name` |
| Stock actuel | somme `StockBalance.quantity` |
| Seuil minimum | `item.min_stock` |
| Statut | `item.stock_status` (low / stockout) |
| Coût unitaire | `item.unit_price` |

**Permission :** tous les rôles authentifiés

---

#### R5 — Budget vs Réalisé (tous chantiers)

**Source :** `GET /api/v1/projects/?status=en_cours` → pour chaque projet `cost-breakdown/`  
**Paramètres :** aucun (tous les chantiers actifs) ou `project` (un seul)  
**Colonnes Excel :**

| Colonne | Source |
|---------|--------|
| Chantier | `project.name` |
| Référence | `project.reference` |
| Budget total | `budget_total` |
| Coût réel | `cost_total` |
| Valeur marché | `contract_value` |
| Marge | `margin` |
| % marge | `margin_percent` |
| Statut budget | over_budget ? "DÉPASSÉ ⚠️" : "OK" |

**Permission :** `reports.budget`

---

#### R6 — Consommation mensuelle par catégorie d'article (🆕 nouveau endpoint)

**Source :** `GET /api/v1/reports/monthly-consumption/?year=2026&project=`  
**Paramètres :** `year` (requis), `project` (optionnel — tous si absent)

**Logique backend :**
```python
# Agréger les sorties completed par mois et catégorie d'article
StockMovement.objects
    .filter(movement_type="sortie", status="completed",
            created_at__year=year)
    .values("created_at__month", "item__category__name")
    .annotate(total_cost=Sum("total_cost"), total_qty=Sum("quantity"))
    .order_by("created_at__month", "item__category__name")
```

**Réponse JSON :**
```json
{
  "year": 2026,
  "months": [
    {
      "month": 1, "month_label": "Janvier",
      "by_category": [
        {"category": "Ciment & liants", "total_cost": "1200000", "total_qty": "2400"},
        ...
      ],
      "month_total": "3500000"
    },
    ...
  ],
  "grand_total": "42000000"
}
```

**Colonnes Excel :** tableau croisé — lignes = mois, colonnes = catégories d'articles, intersections = coût total.  
**Permission :** `reports.financial`

---

#### R7 — Transferts inter-sites

**Source :** `GET /api/v1/stock-movements/?movement_type=transfert`  
**Paramètres :** `date_from`, `date_to`  
**Colonnes CSV/Excel :**

| Colonne | Source |
|---------|--------|
| Date | `created_at` |
| Référence | `reference_number` |
| Article | `item.name` + SKU |
| Quantité | `quantity` |
| Unité | `item.unit` |
| Site source | `source_storage_location.name` |
| Site destination | `destination_storage_location.name` |
| Notes | `notes` |
| Créé par | `created_by.full_name` |

**Permission :** `reports.site`

---

#### R8 — Performance fournisseurs (🆕 nouveau endpoint)

**Source :** `GET /api/v1/reports/supplier-performance/?date_from=&date_to=`  
**Paramètres :** `date_from`, `date_to` (optionnels — défaut : 12 derniers mois)

**Logique backend :**
```python
# Agréger les entrées completed par fournisseur
StockMovement.objects
    .filter(movement_type="entree", status="completed",
            created_at__gte=date_from, created_at__lte=date_to,
            unit_price_at_movement__isnull=False)
    .values("item__supplier_name", "item__supplier__id")
    .annotate(
        nb_livraisons=Count("id"),
        qty_totale=Sum("quantity"),
        valeur_totale=Sum("total_cost"),
        prix_moyen=Avg("unit_price_at_movement"),
        prix_min=Min("unit_price_at_movement"),
        prix_max=Max("unit_price_at_movement"),
        derniere_livraison=Max("created_at"),
    )
    .order_by("-valeur_totale")
```

**Colonnes Excel :**

| Colonne | Source |
|---------|--------|
| Fournisseur | `item__supplier_name` |
| Nb livraisons | `nb_livraisons` |
| Quantité totale | `qty_totale` |
| Valeur totale | `valeur_totale` |
| Prix moyen | `prix_moyen` |
| Prix min | `prix_min` |
| Prix max | `prix_max` |
| Écart prix (max−min) | calculé |
| Dernière livraison | `derniere_livraison` |

**Permission :** `reports.financial`

---

### 9.4 Spécifications Backend

#### 9.4.1 `requirements.txt` — ajouter `openpyxl`

```
openpyxl>=3.1
```

> Pas de lib PDF côté serveur pour le pilote — le PDF est assuré par le navigateur (print-to-PDF). Évite d'ajouter reportlab (~10 MB) ou weasyprint (lourd avec CSS engine).

---

#### 9.4.2 🆕 `api/exports.py` — générateur Excel

```python
# api/exports.py
"""
Générateur de fichiers Excel (openpyxl) pour les rapports Bâtir Pro.
Chaque fonction reçoit des données déjà calculées et retourne une HttpResponse.
"""
import io
from decimal import Decimal
from datetime import date
from django.http import HttpResponse
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side, numbers
from openpyxl.utils import get_column_letter

# ─── Palette de couleurs ────────────────────────────────────
PRIMARY     = "1E3A5F"   # bleu principal (en-tête)
ACCENT      = "E8F0FE"   # bleu très clair (lignes alternées)
WARNING_BG  = "FFF3CD"   # jaune (over_budget)
DANGER_BG   = "FFDEDE"   # rouge clair (rupture / dépassement critique)
SUCCESS_BG  = "D4EDDA"   # vert (OK)
TOTAL_BG    = "F0F4F8"   # gris clair (ligne total)

# ─── Helpers ────────────────────────────────────────────────

def _xlsx_response(filename: str) -> tuple[Workbook, HttpResponse]:
    wb = Workbook()
    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    safe_name = filename.replace(" ", "_")
    response["Content-Disposition"] = f'attachment; filename="{safe_name}"'
    return wb, response


def _header_row(ws, columns: list[str], row: int = 1):
    """Écrit une ligne d'en-tête stylée (fond PRIMARY, texte blanc gras)."""
    for col_idx, label in enumerate(columns, 1):
        cell = ws.cell(row=row, column=col_idx, value=label)
        cell.font = Font(bold=True, color="FFFFFF", size=10)
        cell.fill = PatternFill("solid", fgColor=PRIMARY)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)


def _total_row(ws, row: int, label: str, values: dict[int, Decimal]):
    """Écrit une ligne de total (fond gris, bold)."""
    first_cell = ws.cell(row=row, column=1, value=label)
    first_cell.font = Font(bold=True)
    first_cell.fill = PatternFill("solid", fgColor=TOTAL_BG)
    for col_idx, value in values.items():
        cell = ws.cell(row=row, column=col_idx, value=float(value))
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor=TOTAL_BG)
        cell.number_format = "#,##0.00"
        cell.alignment = Alignment(horizontal="right")


def _autofit_columns(ws, min_width: int = 12, max_width: int = 40):
    """Ajuste la largeur des colonnes selon le contenu."""
    for col in ws.columns:
        col_letter = get_column_letter(col[0].column)
        max_len = max(
            (len(str(cell.value or "")) for cell in col if cell.value),
            default=min_width,
        )
        ws.column_dimensions[col_letter].width = min(max(max_len + 2, min_width), max_width)


def _title_block(ws, title: str, subtitle: str = ""):
    """Insère 2 lignes de titre au-dessus du tableau (avant _header_row)."""
    ws.cell(row=1, column=1, value=title).font = Font(bold=True, size=13, color=PRIMARY)
    if subtitle:
        ws.cell(row=2, column=1, value=subtitle).font = Font(italic=True, size=9, color="6B7280")


def _finalize_xlsx(wb: Workbook, response: HttpResponse) -> HttpResponse:
    buffer = io.BytesIO()
    wb.save(buffer)
    response.write(buffer.getvalue())
    return response


# ─── Rapport R1 : Inventaire valorisé ──────────────────────

def export_stock_valuation(report: dict, currency: str = "XOF") -> HttpResponse:
    COLS = ["Nom", "SKU", "Catégorie", "Quantité", "Coût unitaire", "Valeur totale"]
    wb, response = _xlsx_response(f"inventaire-valorise-{date.today()}.xlsx")
    ws = wb.active
    ws.title = "Inventaire valorisé"

    _title_block(ws,
        f"Inventaire valorisé ({report['method'].upper()})",
        f"Généré le {date.today().strftime('%d/%m/%Y')} — Méthode : {report['method']}")
    _header_row(ws, COLS, row=3)
    ws.freeze_panes = "A4"

    for r_idx, item in enumerate(report["items"], start=4):
        fill = PatternFill("solid", fgColor=ACCENT if r_idx % 2 == 0 else "FFFFFF")
        ws.cell(row=r_idx, column=1, value=item["name"]).fill = fill
        ws.cell(row=r_idx, column=2, value=item["sku"]).fill = fill
        ws.cell(row=r_idx, column=3, value=item.get("category_name") or "—").fill = fill
        c_qty = ws.cell(row=r_idx, column=4, value=float(item["total_quantity"]))
        c_qty.fill = fill; c_qty.number_format = "#,##0.000"
        c_cu = ws.cell(row=r_idx, column=5, value=float(item["unit_cost"]))
        c_cu.fill = fill; c_cu.number_format = "#,##0.00"; c_cu.alignment = Alignment(horizontal="right")
        c_val = ws.cell(row=r_idx, column=6, value=float(item["value"]))
        c_val.fill = fill; c_val.number_format = "#,##0.00"; c_val.alignment = Alignment(horizontal="right")

    total_row = len(report["items"]) + 4
    _total_row(ws, total_row, "TOTAL", {6: Decimal(report["grand_total"])})

    _autofit_columns(ws)
    return _finalize_xlsx(wb, response)


# ─── Rapport R2 : Coût chantier ────────────────────────────

def export_project_cost_breakdown(project, costs: dict, by_category: list) -> HttpResponse:
    wb, response = _xlsx_response(
        f"cout-chantier-{project.reference or project.id}-{date.today()}.xlsx")

    # Feuille 1 — Synthèse
    ws1 = wb.active
    ws1.title = "Synthèse"
    _title_block(ws1, f"Coût chantier — {project.name}",
        f"Ref : {project.reference or '—'} | {date.today().strftime('%d/%m/%Y')}")

    POSTE_MAP = [
        ("Matériaux consommés", "cost_materials"),
        ("Pertes / casses",     "cost_losses"),
        ("Main d'œuvre",        "cost_labour"),
        ("Sous-traitance",      "cost_subcontracting"),
        ("Location équipements","cost_rental"),
        ("Frais généraux",      "cost_overhead"),
    ]
    _header_row(ws1, ["Poste", "Coût réalisé", "Devise"], row=3)
    ws1.freeze_panes = "A4"
    currency = project.currency or "XOF"
    for r_idx, (label, key) in enumerate(POSTE_MAP, start=4):
        ws1.cell(row=r_idx, column=1, value=label)
        c = ws1.cell(row=r_idx, column=2, value=float(costs.get(key) or 0))
        c.number_format = "#,##0.00"; c.alignment = Alignment(horizontal="right")
        ws1.cell(row=r_idx, column=3, value=currency)
    total_r = len(POSTE_MAP) + 4
    _total_row(ws1, total_r, "COÛT TOTAL", {2: Decimal(str(costs.get("cost_total") or 0))})
    meta_r = total_r + 2
    for label, key in [("Budget", "budget_total"), ("Marge", "margin")]:
        ws1.cell(row=meta_r, column=1, value=label).font = Font(italic=True)
        c = ws1.cell(row=meta_r, column=2, value=float(costs.get(key) or 0))
        c.number_format = "#,##0.00"
        meta_r += 1

    # Feuille 2 — Budget vs Réalisé
    ws2 = wb.create_sheet("Budget vs Réalisé")
    _header_row(ws2, ["Catégorie", "Budget", "Réalisé", "Écart", "%", "Statut"], row=1)
    for r_idx, row in enumerate(by_category, start=2):
        ws2.cell(row=r_idx, column=1, value=row.get("label") or row["category"])
        for col, key in [(2, "budget"), (3, "actual"), (4, "variance")]:
            c = ws2.cell(row=r_idx, column=col, value=float(row[key]))
            c.number_format = "#,##0.00"; c.alignment = Alignment(horizontal="right")
        vp = row.get("variance_percent")
        ws2.cell(row=r_idx, column=5, value=f"{vp:.1f}%" if vp is not None else "—")
        statut = "⚠️ DÉPASSÉ" if row.get("over_budget") else "OK"
        c_s = ws2.cell(row=r_idx, column=6, value=statut)
        if row.get("over_budget"):
            c_s.fill = PatternFill("solid", fgColor=WARNING_BG)

    _autofit_columns(ws1); _autofit_columns(ws2)
    return _finalize_xlsx(wb, response)


# ─── Rapport R3 : Historique mouvements ────────────────────

def export_movements(movements_qs, params: dict) -> HttpResponse:
    COLS = ["Date", "Heure", "Référence", "Type", "Article", "SKU",
            "Quantité", "Unité", "Coût unitaire", "Coût total",
            "Source", "Destination", "Chantier", "Statut", "Créé par"]
    date_str = f"{params.get('date_from','')}_au_{params.get('date_to','')}"
    wb, response = _xlsx_response(f"mouvements-{date_str}.xlsx")
    ws = wb.active
    ws.title = "Mouvements"
    _header_row(ws, COLS, row=1)
    ws.freeze_panes = "A2"

    for r_idx, mv in enumerate(movements_qs[:10_000], start=2):
        dt = mv.created_at
        ws.cell(row=r_idx, column=1, value=dt.strftime("%d/%m/%Y"))
        ws.cell(row=r_idx, column=2, value=dt.strftime("%H:%M"))
        ws.cell(row=r_idx, column=3, value=mv.reference_number or "")
        ws.cell(row=r_idx, column=4, value=mv.get_movement_type_display())
        ws.cell(row=r_idx, column=5, value=mv.item.name)
        ws.cell(row=r_idx, column=6, value=mv.item.sku)
        c_q = ws.cell(row=r_idx, column=7, value=float(mv.quantity))
        c_q.number_format = "#,##0.000"
        ws.cell(row=r_idx, column=8, value=str(mv.item.unit) if mv.item.unit else "")
        for col, val in [(9, mv.unit_price_at_movement), (10, mv.total_cost)]:
            if val is not None:
                c = ws.cell(row=r_idx, column=col, value=float(val))
                c.number_format = "#,##0.00"; c.alignment = Alignment(horizontal="right")
        ws.cell(row=r_idx, column=11,
                value=mv.source_storage_location.name if mv.source_storage_location else "")
        ws.cell(row=r_idx, column=12,
                value=mv.destination_storage_location.name if mv.destination_storage_location else "")
        ws.cell(row=r_idx, column=13,
                value=mv.project.name if mv.project else "")
        ws.cell(row=r_idx, column=14, value=mv.get_status_display())
        ws.cell(row=r_idx, column=15,
                value=mv.created_by.user.get_full_name() if mv.created_by else "")

    _autofit_columns(ws)
    return _finalize_xlsx(wb, response)
```

> Les rapports R4 (stock critique), R5 (budget vs réalisé multi-chantier), R6 (consommation mensuelle) et R8 (fournisseurs) suivent le même pattern. Seules les colonnes et la source changent. Le dev implémente les fonctions `export_critical_stock`, `export_all_projects_budget`, `export_monthly_consumption`, `export_supplier_performance` avec la même structure.

---

#### 9.4.3 ⚡ Enrichissement `mail.py` — support pièces jointes

Modifier la signature de `send_mail_via_org_settings()` pour accepter des pièces jointes :

```python
# api/mail.py — modifier send_mail_via_org_settings

def send_mail_via_org_settings(
    cfg,
    recipient_list: list[str],
    subject: str,
    html_body: str,
    attachments: list[tuple[str, bytes, str]] | None = None,   # 🆕 (filename, content, mimetype)
) -> tuple[int, str]:
    """
    attachments : liste de tuples (nom_fichier, contenu_bytes, mime_type)
    Exemple : [("rapport.xlsx",
                 open("rapport.xlsx","rb").read(),
                 "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")]
    """
    # ... logique existante inchangée jusqu'à la construction du message ...
    msg = EmailMessage(subject, html_body, from_email=from_email, to=recipient_list)
    msg.content_subtype = "html"
    if attachments:                    # 🆕
        for filename, content, mime in attachments:
            msg.attach(filename, content, mime)
    # ... suite inchangée ...
```

> Rétrocompatible : `attachments=None` par défaut. Tous les appels existants continuent de fonctionner sans modification.

---

#### 9.4.4 ⚡ `dashboard_cost_overview()` — implémenter le 501

**Fichier :** `api/dashboard_views.py` (lignes 524-527 actuellement `501 Not Implemented`)

```python
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_cost_overview(request):
    """
    GET /api/v1/dashboard/cost-overview/
    Agrège les coûts de tous les projets actifs pour le Dashboard.
    """
    from .project_costs import compute_project_costs
    active_projects = Project.objects.filter(
        status__in=["planifie", "en_cours"]
    ).select_related("agency")

    projects_data = []
    total_budget = total_cost = total_contract = Decimal("0")

    for project in active_projects:
        costs = compute_project_costs(project)
        ct = Decimal(costs["cost_total"])
        bt = Decimal(costs["budget_total"])
        cv = Decimal(costs["contract_value"]) if costs["contract_value"] else None
        total_cost += ct
        total_budget += bt
        if cv:
            total_contract += cv
        projects_data.append({
            "project_id": str(project.id),
            "name": project.name,
            "reference": project.reference,
            "currency": project.currency,
            "cost_total": str(ct),
            "budget_total": str(bt),
            "contract_value": str(cv) if cv else None,
            "margin": costs["margin"],
            "margin_percent": costs["margin_percent"],
            "budget_consumed_percent": costs["budget_consumed_percent"],
            "over_budget": ct > bt if bt > 0 else False,
        })

    global_margin = (total_contract - total_cost) if total_contract > 0 else None
    return Response({
        "total_budget": str(total_budget),
        "total_cost": str(total_cost),
        "total_contract_value": str(total_contract) if total_contract > 0 else None,
        "global_margin": str(global_margin) if global_margin is not None else None,
        "global_margin_percent": (
            round(float(global_margin) / float(total_contract) * 100, 1)
            if global_margin and total_contract > 0 else None
        ),
        "active_projects_count": len(projects_data),
        "projects": projects_data,
    })
```

---

#### 9.4.5 🆕 `ReportViewSet` — nouvelles agrégations + envoi email

Créer un `ReportViewSet` (ViewSet sans modèle) dans `api/views.py` et enregistrer `router.register(r"reports", ReportViewSet, basename="report")` dans `urls.py`.

```python
class ReportViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"], url_path="monthly-consumption")
    def monthly_consumption(self, request):
        """GET /api/v1/reports/monthly-consumption/?year=2026&project="""
        year = int(request.query_params.get("year", date.today().year))
        project_id = request.query_params.get("project")

        qs = StockMovement.objects.filter(
            movement_type=StockMovement.MovementType.SORTIE,
            status=StockMovement.MovementStatus.COMPLETED,
            created_at__year=year,
        ).select_related("item__category")

        if project_id:
            qs = qs.filter(project_id=project_id)

        rows = (qs
            .values("created_at__month", "item__category__name")
            .annotate(total_cost=Sum("total_cost"), total_qty=Sum("quantity"))
            .order_by("created_at__month", "item__category__name"))

        MONTH_LABELS = ["", "Janvier", "Février", "Mars", "Avril", "Mai", "Juin",
                        "Juillet", "Août", "Septembre", "Octobre", "Novembre", "Décembre"]
        months_data = {}
        for row in rows:
            m = row["created_at__month"]
            if m not in months_data:
                months_data[m] = {"month": m, "month_label": MONTH_LABELS[m],
                                   "by_category": [], "month_total": Decimal("0")}
            tc = row["total_cost"] or Decimal("0")
            months_data[m]["by_category"].append({
                "category": row["item__category__name"] or "Sans catégorie",
                "total_cost": str(tc),
                "total_qty": str(row["total_qty"] or Decimal("0")),
            })
            months_data[m]["month_total"] += tc

        result = sorted(months_data.values(), key=lambda x: x["month"])
        for m in result:
            m["month_total"] = str(m["month_total"])
        grand_total = sum(Decimal(m["month_total"]) for m in result)

        return Response({"year": year, "months": result, "grand_total": str(grand_total)})

    @action(detail=False, methods=["get"], url_path="supplier-performance")
    def supplier_performance(self, request):
        """GET /api/v1/reports/supplier-performance/?date_from=&date_to="""
        date_from_str = request.query_params.get("date_from")
        date_to_str   = request.query_params.get("date_to")

        qs = StockMovement.objects.filter(
            movement_type=StockMovement.MovementType.ENTREE,
            status=StockMovement.MovementStatus.COMPLETED,
            unit_price_at_movement__isnull=False,
        )
        if date_from_str:
            qs = qs.filter(created_at__date__gte=date_from_str)
        if date_to_str:
            qs = qs.filter(created_at__date__lte=date_to_str)

        rows = (qs
            .values("item__supplier_name")
            .annotate(
                nb_livraisons=Count("id"),
                qty_totale=Sum("quantity"),
                valeur_totale=Sum("total_cost"),
                prix_moyen=Avg("unit_price_at_movement"),
                prix_min=Min("unit_price_at_movement"),
                prix_max=Max("unit_price_at_movement"),
                derniere_livraison=Max("created_at"),
            )
            .order_by("-valeur_totale"))

        data = []
        for row in rows:
            pmin = row["prix_min"] or Decimal("0")
            pmax = row["prix_max"] or Decimal("0")
            data.append({
                "fournisseur": row["item__supplier_name"] or "Inconnu",
                "nb_livraisons": row["nb_livraisons"],
                "qty_totale": str(row["qty_totale"] or Decimal("0")),
                "valeur_totale": str(row["valeur_totale"] or Decimal("0")),
                "prix_moyen": str(round(row["prix_moyen"] or Decimal("0"), 2)),
                "prix_min": str(pmin),
                "prix_max": str(pmax),
                "ecart_prix": str(pmax - pmin),
                "derniere_livraison": row["derniere_livraison"].date().isoformat()
                    if row["derniere_livraison"] else None,
            })
        return Response({"suppliers": data, "period": {"from": date_from_str, "to": date_to_str}})

    @action(detail=False, methods=["post"], url_path="send-by-email")
    def send_by_email(self, request):
        """
        POST /api/v1/reports/send-by-email/
        Body: { "report_type": "stock_valuation"|"project_cost"|"monthly_consumption",
                "recipient_email": "user@example.com",
                "params": {...} }
        Génère le rapport Excel et l'envoie en pièce jointe.
        Permission : reports.financial ou reports.cost selon le type.
        """
        report_type = request.data.get("report_type")
        recipient   = request.data.get("recipient_email")
        params      = request.data.get("params", {})

        if not recipient:
            return Response({"detail": "recipient_email requis."}, status=400)

        from . import exports
        from .mail import send_mail_via_org_settings
        cfg = OrganizationSettings.objects.first()

        # Générer le contenu Excel selon le type
        if report_type == "stock_valuation":
            from .views import ItemViewSet   # éviter import circulaire si nécessaire
            from .models import Item, StockBalance, StockCostLayer
            # Réutiliser la logique de stock_valuation() directement
            # (déléguer à une fonction partagée si possible)
            report_data = _build_stock_valuation_data()
            response_xlsx = exports.export_stock_valuation(report_data)
            filename = f"inventaire-valorise-{date.today()}.xlsx"
        elif report_type == "monthly_consumption":
            # ... appeler monthly_consumption logic, then export ...
            filename = f"consommation-{params.get('year', date.today().year)}.xlsx"
            response_xlsx = None   # TODO selon report_type
        else:
            return Response({"detail": f"Type inconnu : {report_type}"}, status=400)

        if response_xlsx is None:
            return Response({"detail": "Génération impossible."}, status=500)

        content = b"".join(response_xlsx.streaming_content) \
                  if hasattr(response_xlsx, "streaming_content") \
                  else response_xlsx.content

        sent, kind = send_mail_via_org_settings(
            cfg, [recipient],
            subject=f"[Bâtir Pro] Rapport : {report_type}",
            html_body=f"<p>Veuillez trouver en pièce jointe le rapport <strong>{report_type}</strong> généré le {date.today().strftime('%d/%m/%Y')}.</p>",
            attachments=[(filename, content,
                          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")],
        )
        return Response({"sent": sent, "delivery_kind": kind, "recipient": recipient})
```

> **Note sur `send_by_email`** : la fonction est intentionnellement simple pour le pilote. Elle prend en charge `stock_valuation` en priorité. Le dev l'étend pour les autres types en suivant le même pattern. Une refactorisation future peut extraire la génération de données dans des helpers partagés.

---

#### 9.4.6 🆕 Actions d'export sur les ViewSets existants

**`ItemViewSet`** — ajouter deux actions :

```python
@action(detail=False, methods=["get"], url_path="stock-valuation/export")
def stock_valuation_export(self, request):
    """GET /api/v1/items/stock-valuation/export/  → télécharge Excel"""
    from . import exports
    # Réutiliser la logique de stock_valuation() (factoriser dans _build_stock_valuation_data())
    data = _build_stock_valuation_data()
    cfg = OrganizationSettings.objects.first()
    currency = cfg.default_currency if cfg else "XOF"
    return exports.export_stock_valuation(data, currency)

@action(detail=False, methods=["get"], url_path="critical-stock/export")
def critical_stock_export(self, request):
    """GET /api/v1/items/critical-stock/export/  → télécharge CSV"""
    qs = (Item.objects
          .filter(is_active=True, stock_status__in=["low", "stockout"])   # annotation existante
          .select_related("category", "supplier")
          .annotate(total_stock=Sum("stock_balances__quantity")))
    return exports.export_critical_stock_csv(qs)
```

**`ProjectViewSet`** — ajouter une action :

```python
@action(detail=True, methods=["get"], url_path="cost-breakdown/export")
def cost_breakdown_export(self, request, pk=None):
    """GET /api/v1/projects/{id}/cost-breakdown/export/  → télécharge Excel"""
    from . import exports
    from .project_costs import compute_project_costs
    from .views import _budget_vs_actual_by_category
    project = self.get_object()
    costs = compute_project_costs(project)
    by_cat = _budget_vs_actual_by_category(project)
    return exports.export_project_cost_breakdown(project, costs, by_cat)
```

**`StockMovementViewSet`** — enrichir l'export existant (actuellement limité à la page courante) :

```python
@action(detail=False, methods=["get"], url_path="export")
def export(self, request):
    """GET /api/v1/stock-movements/export/?date_from=&date_to=&movement_type=&project="""
    from . import exports
    qs = self.filter_queryset(
        StockMovement.objects
        .filter(status=StockMovement.MovementStatus.COMPLETED)
        .select_related("item__unit", "item__category",
                         "source_storage_location", "destination_storage_location",
                         "project", "created_by__user")
        .order_by("-created_at")
    )
    params = {
        "date_from": request.query_params.get("date_from", ""),
        "date_to":   request.query_params.get("date_to", ""),
    }
    return exports.export_movements(qs, params)
```

---

#### 9.4.7 Enforcement des permissions RBAC

Les permissions `reports.*` sont définies dans `rbac.py` mais non vérifiées dans les views. Ajouter la vérification dans chaque endpoint d'export :

```python
# Exemple — à répliquer sur chaque endpoint d'export financier
from .rbac import check_permission

@action(detail=False, methods=["get"], url_path="stock-valuation/export")
def stock_valuation_export(self, request):
    if not check_permission(request.user, "reports.financial"):
        return Response({"detail": "Permission refusée."}, status=403)
    ...
```

> Vérifier que `check_permission(user, code)` est la fonction correcte dans `rbac.py` (ou adapter selon le pattern d'enforcement existant dans la codebase).

---

#### 9.4.8 Récapitulatif des nouveaux endpoints

| Endpoint | Méthode | Rôle | Permission |
|----------|---------|------|------------|
| `/api/v1/dashboard/cost-overview/` | GET | ✏️ 501 → implémenté | auth |
| `/api/v1/reports/monthly-consumption/` | GET | 🆕 Consommation par mois/catégorie | `reports.financial` |
| `/api/v1/reports/supplier-performance/` | GET | 🆕 Agrégats fournisseurs | `reports.financial` |
| `/api/v1/reports/send-by-email/` | POST | 🆕 Envoie rapport Excel par email | `reports.financial` |
| `/api/v1/items/stock-valuation/export/` | GET | 🆕 Télécharge inventaire valorisé Excel | `reports.financial` |
| `/api/v1/items/critical-stock/export/` | GET | 🆕 Télécharge stock critique CSV | auth |
| `/api/v1/projects/{id}/cost-breakdown/export/` | GET | 🆕 Télécharge coût chantier Excel | `reports.cost` |
| `/api/v1/stock-movements/export/` | GET | ✏️ Enrichi (export complet, plus limité) | auth |

---

### 9.5 Spécifications Frontend

#### 9.5.1 Nouveaux types TypeScript (`src/types/api.ts`)

```ts
// ── Rapport mensuel ──────────────────────────────────────
export interface MonthlyConsumptionRow {
  category: string;
  total_cost: string;
  total_qty: string;
}
export interface MonthlyConsumptionMonth {
  month: number;
  month_label: string;
  by_category: MonthlyConsumptionRow[];
  month_total: string;
}
export interface MonthlyConsumptionReport {
  year: number;
  months: MonthlyConsumptionMonth[];
  grand_total: string;
}

// ── Performance fournisseurs ─────────────────────────────
export interface SupplierPerformanceRow {
  fournisseur: string;
  nb_livraisons: number;
  qty_totale: string;
  valeur_totale: string;
  prix_moyen: string;
  prix_min: string;
  prix_max: string;
  ecart_prix: string;
  derniere_livraison: ISODate | null;
}
export interface SupplierPerformanceReport {
  suppliers: SupplierPerformanceRow[];
  period: { from: string | null; to: string | null };
}

// ── Dashboard cost overview ──────────────────────────────
export interface DashboardCostOverviewProject {
  project_id: UUID;
  name: string;
  reference: string;
  currency: string;
  cost_total: string;
  budget_total: string;
  contract_value: string | null;
  margin: string | null;
  margin_percent: number | null;
  budget_consumed_percent: number | null;
  over_budget: boolean;
}
export interface DashboardCostOverview {
  total_budget: string;
  total_cost: string;
  total_contract_value: string | null;
  global_margin: string | null;
  global_margin_percent: number | null;
  active_projects_count: number;
  projects: DashboardCostOverviewProject[];
}

// ── Envoi email ──────────────────────────────────────────
export interface SendReportEmailPayload {
  report_type: 'stock_valuation' | 'project_cost' | 'monthly_consumption' | 'supplier_performance';
  recipient_email: string;
  params?: Record<string, string | number>;
}
export interface SendReportEmailResult {
  sent: boolean;
  delivery_kind: string;
  recipient: string;
}
```

---

#### 9.5.2 Nouveaux services API (`src/lib/api/services.ts`)

```ts
reports: {
  monthlyConsumption: (params: { year: number; project?: string }) =>
    unwrap(http.get<MonthlyConsumptionReport>('reports/monthly-consumption/', { params })),
  supplierPerformance: (params?: { date_from?: string; date_to?: string }) =>
    unwrap(http.get<SupplierPerformanceReport>('reports/supplier-performance/', { params })),
  sendByEmail: (payload: SendReportEmailPayload) =>
    unwrap(http.post<SendReportEmailResult>('reports/send-by-email/', payload)),
},
dashboard: {
  // ... services existants ...
  costOverview: () =>
    unwrap(http.get<DashboardCostOverview>('dashboard/cost-overview/')),
},
// Ajouter dans items:
// stockValuationExportUrl: () => `${BASE_URL}items/stock-valuation/export/`
// criticalStockExportUrl: () => `${BASE_URL}items/critical-stock/export/`
// Ajouter dans projects:
// costBreakdownExportUrl: (id: UUID) => `${BASE_URL}projects/${id}/cost-breakdown/export/`
// Ajouter dans stockMovements:
// exportUrl: (params) => `${BASE_URL}stock-movements/export/?${new URLSearchParams(params)}`
```

> **Pattern pour le téléchargement de fichier Excel :** le frontend redirige simplement vers l'URL avec le token JWT en header. La méthode la plus simple est d'ouvrir l'URL dans un onglet ou d'utiliser `fetch` + `URL.createObjectURL` + clic programmatique. Voir §9.5.3 pour l'implémentation.

---

#### 9.5.3 🆕 `ReportsPage.tsx` — hub central

**Route :** `/reports`  
**Ajouter dans `Sidebar.tsx` :** lien "Rapports" avec icône `FileBarChart` après "Alertes".  
**Ajouter dans `App.tsx` :** `<Route path="/reports" element={<ReportsPage />} />`

**Layout de la page :**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  RAPPORTS & EXPORTS                                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐     │
│  │ 📦 Inventaire    │  │ 💰 Coût chantier  │  │ 📋 Mouvements    │     │
│  │ valorisé         │  │                  │  │                  │     │
│  │                  │  │ Chantier [▼]     │  │ Du [date] Au [▼] │     │
│  │ Méthode : CUMP   │  │                  │  │ Type [▼]         │     │
│  │                  │  │                  │  │                  │     │
│  │ [⬇ Excel][🖨 Imp]│  │ [⬇ Excel][🖨 Imp]│  │ [⬇ CSV][⬇ Excel] │     │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘     │
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐     │
│  │ ⚠️ Stock critique │  │ 📊 Budget vs     │  │ 📅 Consommation  │     │
│  │                  │  │ Réalisé          │  │ mensuelle        │     │
│  │ Snapshot actuel  │  │                  │  │ Année [2026▼]    │     │
│  │                  │  │ Tous chantiers   │  │                  │     │
│  │ [⬇ CSV][🖨 Imp]  │  │ [⬇ Excel][🖨 Imp]│  │ [⬇ Excel]        │     │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘     │
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐                           │
│  │ 🚚 Transferts    │  │ 🏭 Fournisseurs   │                           │
│  │ inter-sites      │  │                  │                           │
│  │ Du [date] Au [▼] │  │ Du [date] Au [▼] │                           │
│  │                  │  │                  │                           │
│  │ [⬇ CSV][⬇ Excel] │  │ [⬇ Excel]        │                           │
│  └──────────────────┘  └──────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────┘
```

**Comportement des boutons de téléchargement Excel :**

```tsx
// Helper — téléchargement d'un fichier depuis une URL d'API (avec auth)
const downloadFile = async (url: string, filename: string) => {
  setLoading(true);
  try {
    const token = getAccessToken();  // depuis authStore ou localStorage
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(objectUrl);
  } catch (err) {
    // Afficher une erreur toast
  } finally {
    setLoading(false);
  }
};
```

**Comportement des boutons CSV :** utiliser le pattern natif existant de `MovementsPage.tsx` (Blob + URL.createObjectURL).

**Comportement du bouton Impression :**

```tsx
const handlePrint = () => window.print();
// + CSS @media print pour masquer le reste de la page
```

**Envoi par email — modal :**

Un bouton "📧 Envoyer par email" dans chaque carte ouvre une modal :
```
┌─────────────────────────────────────┐
│ Envoyer "Inventaire valorisé"       │
│                                     │
│ Destinataire : [ email@exemple.com ]│
│                                     │
│              [Annuler] [Envoyer]    │
└─────────────────────────────────────┘
```
- Appelle `apiServices.reports.sendByEmail(...)`.
- Affiche "Email envoyé ✓" ou "Erreur d'envoi ✗" selon le résultat.

---

#### 9.5.4 Exports depuis les pages existantes

**`InventoryPage.tsx`** — brancher le bouton "Exporter" existant ([ligne 277](inventory-client-main/src/pages/InventoryPage.tsx#L277)) :

```tsx
// Remplacer le onClick vide actuel par :
onClick={() => downloadFile(
  `${BASE_URL}items/stock-valuation/export/`,
  `inventaire-valorise-${new Date().toISOString().split('T')[0]}.xlsx`
)}
```

**`MovementsPage.tsx`** — enrichir l'export existant (actuellement limité à la page courante) :

Ajouter un second bouton "Exporter tout (filtres actifs)" qui appelle l'endpoint backend :

```tsx
const exportAll = () => downloadFile(
  `${BASE_URL}stock-movements/export/?${new URLSearchParams({
    ...(dateFrom ? { date_from: dateFrom } : {}),
    ...(movementType ? { movement_type: movementType } : {}),
    ...(projectFilter ? { project: projectFilter } : {}),
  })}`,
  `mouvements-complet-${new Date().toISOString().split('T')[0]}.xlsx`
);
```

**`ProjectDetailPage.tsx`** — ajouter un bouton export dans l'onglet Coûts :

```tsx
// Dans CoutsTab, ajouter à côté des cartes :
<button onClick={() => downloadFile(
  `${BASE_URL}projects/${projectId}/cost-breakdown/export/`,
  `cout-chantier-${project.reference}.xlsx`
)}>
  <Download className="w-4 h-4" /> Exporter Excel
</button>
```

---

#### 9.5.5 CSS `@media print` (`src/index.css`)

```css
@media print {
  /* Masquer la navigation, sidebar, boutons d'action */
  nav, aside, .sidebar, .topnav, button, [data-print-hidden] {
    display: none !important;
  }

  /* Pleine largeur pour le contenu imprimé */
  main, .print-content {
    width: 100% !important;
    margin: 0 !important;
    padding: 0 !important;
  }

  /* En-tête d'impression */
  .print-header {
    display: block !important;
  }

  /* Éviter les coupures de page dans les tableaux */
  tr, .report-card {
    page-break-inside: avoid;
  }

  /* Forcer les couleurs pour l'impression */
  * {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
}

/* Masqué à l'écran, visible à l'impression */
.print-header {
  display: none;
}
```

Chaque rapport imprimable doit avoir un `<div className="print-header">` contenant le titre, la date et le logo (ou nom de l'org).

---

#### 9.5.6 Route et permissions

**`App.tsx`** — ajouter :
```tsx
<Route path="/reports" element={
  <RequirePermission anyOf={['reports.financial', 'reports.cost', 'reports.budget', 'reports.site']}>
    <ReportsPage />
  </RequirePermission>
} />
```

**`Sidebar.tsx`** — ajouter l'entrée de navigation (après Alertes) :
```tsx
{ id: 'reports', label: 'Rapports', icon: FileBarChart2, path: '/reports' },
```

> La page est visible pour tout rôle ayant **au moins une** permission rapport. Les cartes individuelles vérifient la permission fine côté client (masquer le bouton si pas la bonne permission) ET côté serveur (403 si l'endpoint est appelé sans permission).

---

### 9.6 Dépendances

| Dépendance | Impact |
|------------|--------|
| Section 3 (Inventaire) ✅ | `Item.min_stock`, `stock_status`, `unit_price` — sources R1, R4. |
| Section 4 (Mouvements) ✅ | `StockMovement` filtrable — source R3, R7. `total_cost` alimenté par Section 7. |
| Section 5 (Projets) ✅ | `Project.budget_amount`, `contract_value` — sources R2, R5. |
| Section 6 (Lieux) ✅ | `StorageLocation` — source R3, R7 (source/destination). |
| Section 7 (Coûts) ✅ | `cost-breakdown/`, `project_costs.py`, `stock-valuation/` — sources directes R1, R2, R5. |
| Section 8 (Alertes) ✅ | `OrganizationSettings.smtp_*` — utilisé par `send-by-email/`. |
| Section 11 (Mobile) ⏳ | Les rapports générés ici seront consultables en lecture depuis le mobile. L'export fichier reste web. |

---

### 9.7 Priorité d'implémentation

| Étape | Tâche | Estimation |
|-------|-------|------------|
| 1 | **Backend : `requirements.txt`** — ajouter `openpyxl` + `pip install` | 0.25 j |
| 2 | **Backend : `api/exports.py`** — helpers + R1 (inventaire valorisé) + R2 (coût chantier) | 1.5 j |
| 3 | **Backend : `api/exports.py`** — R3 (mouvements) + R4 (stock critique) + R5 (budget vs réalisé) | 1 j |
| 4 | **Backend : `api/exports.py`** — R6 (consommation mensuelle) + R8 (fournisseurs) | 0.75 j |
| 5 | **Backend : actions d'export sur ViewSets existants** (ItemViewSet, ProjectViewSet, StockMovementViewSet) | 1 j |
| 6 | **Backend : `ReportViewSet`** — `monthly-consumption/`, `supplier-performance/`, `send-by-email/` | 1.5 j |
| 7 | **Backend : `dashboard_cost_overview()`** — implémenter le 501 | 0.5 j |
| 8 | **Backend : `mail.py`** — ajout du paramètre `attachments` | 0.25 j |
| 9 | **Backend : enforcement permissions RBAC** sur les nouveaux endpoints | 0.5 j |
| 10 | **Backend : tests** (Excel non vide, email envoyé, agrégations correctes) | 1 j |
| 11 | **Frontend : types TS + services** (tous les nouveaux types) | 0.5 j |
| 12 | **Frontend : `ReportsPage.tsx`** — hub 8 cartes, `downloadFile`, CSV, envoi email | 2.5 j |
| 13 | **Frontend : CSS `@media print`** + print-header dans chaque rapport | 0.5 j |
| 14 | **Frontend : brancher exports** dans `InventoryPage`, `MovementsPage`, `ProjectDetailPage` | 1 j |
| 15 | **Frontend : route + sidebar + permissions UI** | 0.25 j |
| 16 | **Frontend : `DashboardPage`** — brancher `cost-overview/` (widget coûts global) | 0.75 j |
| **Total estimé** | | **~14 jours** |

> **Chemin critique :** étapes 1 → 2 → 5 (openpyxl + exports + endpoints). Sans elles, aucun téléchargement n'est possible. L'étape 12 (ReportsPage) peut démarrer dès que les premiers endpoints d'export sont prêts.

---

### 9.8 Critères de validation (Definition of Done)

**Backend — génération Excel :**
- [ ] `GET /items/stock-valuation/export/` retourne un fichier `.xlsx` valide, avec en-tête stylé et ligne total.
- [ ] `GET /projects/{id}/cost-breakdown/export/` retourne un fichier `.xlsx` avec 2 feuilles (Synthèse + Budget vs Réalisé).
- [ ] `GET /stock-movements/export/` retourne un `.xlsx` avec toutes les lignes filtrées (pas seulement la page courante), max 10 000 lignes.
- [ ] `GET /items/critical-stock/export/` retourne un `.csv` des articles `low` et `stockout`.
- [ ] Les fichiers Excel s'ouvrent sans erreur dans Excel et LibreOffice.

**Backend — nouvelles agrégations :**
- [ ] `GET /reports/monthly-consumption/?year=2026` retourne 12 mois avec totaux par catégorie et grand total.
- [ ] `GET /reports/supplier-performance/` retourne les fournisseurs triés par valeur décroissante avec prix min/max/moyen.
- [ ] `GET /dashboard/cost-overview/` ne retourne plus 501 — retourne les coûts agrégés des projets actifs.

**Backend — email :**
- [ ] `POST /reports/send-by-email/` envoie un email avec pièce jointe `.xlsx` et retourne `{"sent": true}`.
- [ ] Si `email_alerts_enabled=False` ou SMTP mal configuré, retourne `{"sent": false}` sans lever d'exception.

**Backend — permissions :**
- [ ] Un utilisateur sans `reports.financial` reçoit HTTP 403 sur les endpoints d'export financier.
- [ ] Un magasinier (sans permission financière) peut exporter le stock critique et les mouvements.

**Frontend — ReportsPage :**
- [ ] La page est accessible depuis la sidebar à `/reports`.
- [ ] Chaque carte affiche des paramètres (sélecteur projet, plage de dates, année selon le rapport).
- [ ] Le bouton "Exporter Excel" déclenche le téléchargement du fichier (pas de navigation).
- [ ] Le bouton "Exporter CSV" génère le CSV côté client.
- [ ] Le bouton "Imprimer" ouvre la fenêtre d'impression navigateur avec la navigation masquée.
- [ ] Le bouton "Envoyer par email" ouvre une modal, envoie et affiche le résultat.

**Frontend — pages existantes :**
- [ ] Le bouton "Exporter" de `InventoryPage` télécharge l'inventaire valorisé Excel (plus non-fonctionnel).
- [ ] `MovementsPage` propose "Exporter tout" (filtres actifs, toutes pages) en plus de "Exporter la page courante".
- [ ] L'onglet Coûts de `ProjectDetailPage` a un bouton "Exporter Excel".

**Frontend — print :**
- [ ] L'impression d'un rapport masque la sidebar et les boutons.
- [ ] Un en-tête "Bâtir Pro — [Nom du rapport] — [Date]" apparaît uniquement à l'impression.
- [ ] Les tableaux ne sont pas coupés en milieu de ligne.
