"""
Moteur de generation des alertes -- Section 8.
Appele :
- apres chaque mouvement completed (depuis _apply_movement_to_cost_layers)
- a la demande via POST /alerts/refresh/ (depuis AlertViewSet)

Pas de Celery. Generation synchrone a la demande.
"""

from decimal import Decimal

from django.utils import timezone
from django.db.models import Sum

from .models import Alert, Item, StockBalance, StockMovement, Project, OrganizationSettings

ZERO = Decimal("0")


def _settings():
    """Singleton OrganizationSettings ou None."""
    return OrganizationSettings.objects.first()


# ---------------------------------------------------------------------------
# _upsert_alert / _resolve
# ---------------------------------------------------------------------------

def _upsert_alert(fingerprint, alert_type, severity, title, message,
                  item=None, project=None, stock_movement=None) -> tuple:
    """
    Cree l'alerte si elle n'existe pas encore (active).
    Retourne (alert_instance, created_bool).
    Si elle existe deja et est active, met a jour updated_at.
    """
    existing = Alert.objects.filter(
        fingerprint=fingerprint,
        status__in=[Alert.Status.UNREAD, Alert.Status.READ]
    ).first()
    if existing:
        existing.save(update_fields=["updated_at"])
        return existing, False
    alert = Alert.objects.create(
        fingerprint=fingerprint, alert_type=alert_type, severity=severity,
        title=title, message=message,
        item=item, project=project, stock_movement=stock_movement,
    )
    if severity == Alert.Severity.CRITICAL:
        send_alert_email(alert)
    return alert, True


def _resolve(fingerprint: str):
    """Resout automatiquement toutes les alertes actives portant ce fingerprint."""
    Alert.objects.filter(
        fingerprint=fingerprint,
        status__in=[Alert.Status.UNREAD, Alert.Status.READ]
    ).update(status=Alert.Status.RESOLVED, resolved_at=timezone.now())


def _total_stock(item) -> Decimal:
    """Stock total d'un article (tous emplacements cumules)."""
    return StockBalance.objects.filter(item=item).aggregate(
        t=Sum("quantity"))["t"] or ZERO


# ---------------------------------------------------------------------------
# Generateurs individuels
# ---------------------------------------------------------------------------

def check_stock_alerts(item) -> dict:
    """
    Verifie low_stock et stockout pour un article donne.
    Appele apres chaque mouvement completed.
    Retourne {"created": int, "resolved": int}.
    """
    total = _total_stock(item)
    created = 0
    resolved = 0

    stockout_fp = f"stockout_{item.id}"
    low_fp = f"low_stock_{item.id}"

    if total <= ZERO:
        _resolve(low_fp)
        _, new = _upsert_alert(
            fingerprint=stockout_fp,
            alert_type=Alert.AlertType.STOCKOUT,
            severity=Alert.Severity.CRITICAL,
            title=f"Rupture de stock -- {item.name}",
            message=(
                f"{item.name} ({item.sku}) -- rupture de stock complete. "
                "Aucune unite disponible dans tous les depots."
            ),
            item=item,
        )
        if new:
            created += 1
    else:
        _resolve(stockout_fp)
        if item.min_stock and item.min_stock > ZERO and total < item.min_stock:
            _, new = _upsert_alert(
                fingerprint=low_fp,
                alert_type=Alert.AlertType.LOW_STOCK,
                severity=Alert.Severity.WARNING,
                title=f"Stock bas -- {item.name}",
                message=(
                    f"{item.name} ({item.sku}) -- stock restant : "
                    f"{total:g} {item.unit.name if item.unit_id else ''} "
                    f"(seuil minimum : {item.min_stock:g}). "
                    "Reapprovisionnement recommande."
                ),
                item=item,
            )
            if new:
                created += 1
        else:
            _resolve(low_fp)
            resolved += 1

    return {"created": created, "resolved": resolved}


def check_budget_alert(project) -> dict:
    """
    Verifie le depassement de budget pour un projet.
    Appele apres chaque sortie completed sur un projet.
    """
    if not project or not project.auto_alerts_enabled:
        return {"created": 0, "resolved": 0}

    fp = f"budget_overrun_{project.id}"
    try:
        from .project_costs import compute_project_costs_simple
        costs = compute_project_costs_simple(project)
        cost_total = costs["cost_total"]
        budget_total = costs["budget_total"]
    except Exception:
        return {"created": 0, "resolved": 0}

    if budget_total and budget_total > ZERO and cost_total > budget_total:
        ecart = cost_total - budget_total
        pct = round(float(ecart) / float(budget_total) * 100, 1)
        _, new = _upsert_alert(
            fingerprint=fp,
            alert_type=Alert.AlertType.BUDGET_OVERRUN,
            severity=Alert.Severity.CRITICAL,
            title=f"Depassement de budget -- {project.name}",
            message=(
                f"Chantier {project.name} -- cout reel ({cost_total:,.0f} {project.currency}) "
                f"depasse le budget ({budget_total:,.0f}). "
                f"Ecart : +{ecart:,.0f} XOF (+{pct} %)."
            ),
            project=project,
        )
        return {"created": int(new), "resolved": 0}
    else:
        _resolve(fp)
        return {"created": 0, "resolved": 1}


def generate_new_delivery_alert(movement) -> bool:
    """Alerte info a chaque livraison receptionnee."""
    cfg = _settings()
    if cfg and not cfg.new_delivery_alerts_enabled:
        return False
    fp = f"new_delivery_{movement.id}"
    depot = movement.destination_storage_location
    _, created = _upsert_alert(
        fingerprint=fp,
        alert_type=Alert.AlertType.NEW_DELIVERY,
        severity=Alert.Severity.INFO,
        title=f"Livraison receptionnee -- {movement.item.name}",
        message=(
            f"Livraison receptionnee : {movement.quantity:g} "
            f"{movement.item.unit.name if movement.item.unit_id else ''} "
            f"de {movement.item.name} "
            f"au depot {depot.name if depot else 'N/A'}. "
            f"Bon : {movement.reference_number or '--'}."
        ),
        item=movement.item, stock_movement=movement,
    )
    return created


def generate_inventory_gap_alert(movement) -> bool:
    """Alerte pour un ajustement perte significatif."""
    cfg = _settings()
    if not movement.total_cost:
        return False
    threshold_cost = cfg.inventory_gap_min_cost if cfg else Decimal("50000")
    if movement.total_cost < threshold_cost:
        return False
    fp = f"inventory_gap_{movement.id}"
    _, created = _upsert_alert(
        fingerprint=fp,
        alert_type=Alert.AlertType.INVENTORY_GAP,
        severity=Alert.Severity.WARNING,
        title=f"Ecart d'inventaire -- {movement.item.name}",
        message=(
            f"Ajustement (perte) : -{movement.quantity:g} "
            f"{movement.item.unit.name if movement.item.unit_id else ''} "
            f"de {movement.item.name}. "
            f"Perte valorisee : {movement.total_cost:,.0f} XOF."
        ),
        item=movement.item, stock_movement=movement,
    )
    return created


def generate_abnormal_movement_alert(movement) -> bool:
    """Alerte pour une sortie de valeur anormalement elevee."""
    cfg = _settings()
    threshold = cfg.abnormal_movement_threshold if cfg else Decimal("500000")
    if not movement.total_cost or movement.total_cost < threshold:
        return False
    fp = f"abnormal_movement_{movement.id}"
    _, created = _upsert_alert(
        fingerprint=fp,
        alert_type=Alert.AlertType.ABNORMAL_MOVEMENT,
        severity=Alert.Severity.WARNING,
        title=f"Sortie de valeur elevee -- {movement.item.name}",
        message=(
            f"Sortie de {movement.quantity:g} "
            f"{movement.item.unit.name if movement.item.unit_id else ''} "
            f"de {movement.item.name} -- valeur : {movement.total_cost:,.0f} XOF. "
            f"Chantier : {movement.project.name if movement.project else '--'}. "
            f"Ref : {movement.reference_number or movement.id}."
        ),
        item=movement.item, project=movement.project, stock_movement=movement,
    )
    return created


def generate_pending_approval_alerts() -> int:
    """
    Verifie les mouvements pending depuis trop longtemps.
    Appele uniquement par refresh/ global.
    """
    cfg = _settings()
    threshold_h = cfg.pending_approval_threshold_hours if cfg else 24
    cutoff = timezone.now() - timezone.timedelta(hours=threshold_h)
    stale = StockMovement.objects.filter(
        status=StockMovement.MovementStatus.PENDING,
        created_at__lte=cutoff,
    ).select_related("item", "project", "created_by__user")
    created = 0
    for mv in stale:
        fp = f"pending_approval_{mv.id}"
        age_h = int((timezone.now() - mv.created_at).total_seconds() / 3600)
        demandeur = mv.created_by.get_full_name() if mv.created_by else "--"
        _, new = _upsert_alert(
            fingerprint=fp,
            alert_type=Alert.AlertType.PENDING_APPROVAL,
            severity=Alert.Severity.WARNING,
            title=f"Validation en attente -- {mv.item.name}",
            message=(
                f"Mouvement {mv.reference_number or mv.id} en attente d'approbation "
                f"depuis {age_h}h. Demandeur : {demandeur}. "
                f"Article : {mv.item.name}, Qte : {mv.quantity:g}."
            ),
            item=mv.item, project=mv.project, stock_movement=mv,
        )
        if new:
            created += 1
    # Resoudre automatiquement les pending_approval dont le mouvement est fini
    for alert_obj in Alert.objects.filter(
        alert_type=Alert.AlertType.PENDING_APPROVAL,
        status__in=[Alert.Status.UNREAD, Alert.Status.READ]
    ).select_related("stock_movement"):
        if alert_obj.stock_movement and alert_obj.stock_movement.status in (
            StockMovement.MovementStatus.COMPLETED,
            StockMovement.MovementStatus.REJECTED,
        ):
            _resolve(alert_obj.fingerprint)
    return created


# ---------------------------------------------------------------------------
# run_all() -- pour POST /alerts/refresh/
# ---------------------------------------------------------------------------

def run_all() -> dict:
    """
    Lance tous les generateurs. Appele par POST /alerts/refresh/.
    Retourne un bilan de generation.
    """
    stock_created = 0
    stock_resolved = 0
    for item in Item.objects.filter(is_active=True):
        r = check_stock_alerts(item)
        stock_created += r["created"]
        stock_resolved += r["resolved"]

    budget_created = 0
    budget_resolved = 0
    for project in Project.objects.filter(
        auto_alerts_enabled=True,
        status__in=["en_cours", "planification"]
    ):
        r = check_budget_alert(project)
        budget_created += r["created"]
        budget_resolved += r["resolved"]

    pending_created = generate_pending_approval_alerts()

    return {
        "stock_alerts_created": stock_created,
        "stock_alerts_resolved": stock_resolved,
        "budget_alerts_created": budget_created,
        "budget_alerts_resolved": budget_resolved,
        "pending_approval_alerts_created": pending_created,
    }


# ---------------------------------------------------------------------------
# Envoi email pour alertes critiques
# ---------------------------------------------------------------------------

def send_alert_email(alert: Alert) -> bool:
    """
    Envoie un email pour une alerte critique si email_alerts_enabled.
    """
    if alert.severity != Alert.Severity.CRITICAL:
        return False
    cfg = _settings()
    if not cfg or not cfg.email_alerts_enabled:
        return False
    if alert.email_sent:
        return False

    from .mail import send_mail_via_org_settings
    dest = cfg.notification_email
    if not dest:
        return False

    subject = f"[Batir Pro] Alerte critique : {alert.title}"
    body = (
        f'<h2 style="color:#dc2626">&#9888; Alerte critique</h2>'
        f"<p><strong>{alert.title}</strong></p>"
        f"<p>{alert.message}</p><hr>"
        f'<p style="color:#6b7280;font-size:12px">'
        f"Alerte generee le {alert.created_at.strftime('%d/%m/%Y a %H:%M')} -- Batir Pro</p>"
    )
    sent_count, delivery_kind = send_mail_via_org_settings(
        subject=subject,
        html_body=body,
        recipient_list=[dest],
    )
    if sent_count > 0:
        alert.email_sent = True
        alert.email_sent_at = timezone.now()
        alert.save(update_fields=["email_sent", "email_sent_at", "updated_at"])
    return sent_count > 0
