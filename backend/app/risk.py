"""Risk scoring is a transparent decision aid, not a proof of misuse or non-use."""
from datetime import timedelta
from sqlalchemy.orm import Session, joinedload
from .models import Entitlement, Account, utcnow

PRIVILEGED = {"admin", "owner", "root", "sysadmin", "write_all", "maintain"}
EXPECTED_ACCESS = {
    "Finance": {"finance", "erp", "billing", "payroll", "shared"},
    "Engineering": {"github", "dev", "staging", "linux", "ci", "shared"},
    "HR": {"hr", "people", "payroll", "shared"},
    "Sales": {"crm", "sales", "shared"},
    "IT": {"github", "linux", "windows", "active directory", "dev", "staging", "shared", "production", "admin"},
}

def outside_role(department: str | None, resource: str) -> bool:
    if not department or department not in EXPECTED_ACCESS:
        return False  # No policy means unknown, not a violation
    resource_lower = resource.lower()
    return not any(key in resource_lower for key in EXPECTED_ACCESS[department])

def recompute(db: Session) -> dict:
    entitlements = db.query(Entitlement).options(joinedload(Entitlement.account).joinedload(Account.employee)).all()
    now = utcnow()
    anomaly_by_id = {}
    active = [e for e in entitlements if e.active]
    # Isolation Forest is optional, only if there is a non-trivial population.
    if len(active) >= 20:
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            departments = {name: idx for idx, name in enumerate(sorted({(e.account.employee.department if e.account.employee else "Unknown") for e in active}))}
            features = np.array([
                [departments[e.account.employee.department if e.account.employee else "Unknown"],
                 1 if e.permission.lower() in PRIVILEGED else 0,
                 {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(e.sensitivity.lower(), 1),
                 min((now - e.last_used_at).days, 365) if e.last_used_at else -1,
                 1 if e.account.employee is None else 0]
                for e in active], dtype=float)
            flags = IsolationForest(n_estimators=80, contamination=0.12, random_state=42).fit_predict(features)
            anomaly_by_id = {e.id: (1.0 if flag == -1 else 0.0) for e, flag in zip(active, flags)}
        except (ImportError, ValueError):
            pass
    for e in entitlements:
        if not e.active:
            e.risk_score = 0
            e.risk_level = "inactive"
            e.reasons = ["Entitlement is not currently reported as active"]
            e.anomaly_score = None
            continue
        score, reasons = 0, []
        emp = e.account.employee
        if emp is None:
            score += 40
            reasons.append("Orphaned account: no verified employee identity mapping (+40)")
        elif emp.status.lower() != "active":
            score += 45
            reasons.append("Employee lifecycle status is not active (+45)")
        privileged = e.permission.lower() in PRIVILEGED
        if privileged:
            score += 20
            reasons.append("Privileged role requires additional scrutiny (+20)")
        if e.sensitivity.lower() in {"high", "critical"}:
            score += 15
            reasons.append("High-sensitivity resource (+15)")
        if emp and outside_role(emp.department, e.resource):
            score += 25
            reasons.append("Resource outside configured department access policy (+25)")
        if e.last_used_at:
            days = (now - e.last_used_at).days
            if days >= 90:
                score += 25
                reasons.append(f"Verified resource-use evidence is {days} days old (+25)")
            elif days >= 60:
                score += 10
                reasons.append(f"Verified resource-use evidence is {days} days old (+10)")
        else:
            reasons.append("Resource-use evidence unavailable; cannot establish inactivity")
        if e.account.last_login and (now - e.account.last_login).days >= 90:
            score += 10
            reasons.append("Account last login older than 90 days (+10)")
        flag = anomaly_by_id.get(e.id)
        if flag == 1.0:
            score += 10
            reasons.append("Exploratory Isolation Forest anomaly flag (+10; unvalidated)")
        e.risk_score = min(score, 100)
        e.risk_level = "high" if e.risk_score >= 70 else "medium" if e.risk_score >= 35 else "low"
        e.reasons = reasons or ["No configured risk rules triggered"]
        e.anomaly_score = flag
    db.flush()
    return {"analyzed": len(entitlements), "high": sum(e.risk_level == "high" for e in active), "medium": sum(e.risk_level == "medium" for e in active), "anomaly_model_used": len(active) >= 20 and bool(anomaly_by_id)}
