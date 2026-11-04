import csv
import io
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy.orm import Session
from .models import Employee, Account, Entitlement, Activity, utcnow

REQUIRED = {
    "employees": {"code", "name", "email", "department", "job_title", "status"},
    "accounts": {"platform", "username", "employee_code", "status"},
    "entitlements": {"platform", "username", "resource", "permission", "sensitivity"},
    "activities": {"platform", "username", "resource", "event_type", "occurred_at", "source"},
}

def parse_dt(value):
    if not value or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return (parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed).replace(tzinfo=None)
    except ValueError:
        raise ValueError(f"Invalid date: {value}. Use ISO-8601 format")

def import_csv(db: Session, kind: str, data: bytes):
    if kind not in REQUIRED:
        raise HTTPException(404, "Unknown CSV dataset")
    if len(data) > 2_000_000:
        raise HTTPException(413, "CSV upload limit is 2 MB")
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
        if not reader.fieldnames or not REQUIRED[kind].issubset(set(reader.fieldnames)):
            raise HTTPException(422, f"Required columns: {', '.join(sorted(REQUIRED[kind]))}")
        rows = list(reader)
        if len(rows) > 3000:
            raise HTTPException(413, "Max 3000 rows per file")
    except UnicodeDecodeError:
        raise HTTPException(422, "CSV must be UTF-8")
    count = 0
    try:
        for i, row in enumerate(rows, 2):
            if kind == "employees":
                obj = db.query(Employee).filter_by(code=row["code"].strip()).first()
                if not obj:
                    obj = Employee(code=row["code"].strip()); db.add(obj)
                for k in ("name", "email", "department", "job_title", "status"):
                    setattr(obj, k, row[k].strip())
                obj.manager_username = row.get("manager_username", "reviewer").strip() or "reviewer"
            elif kind == "accounts":
                employee_code = row["employee_code"].strip()
                emp = db.query(Employee).filter_by(code=employee_code).first() if employee_code else None
                if employee_code and not emp:
                    raise ValueError(f"Unknown employee_code {employee_code}")
                obj = db.query(Account).filter_by(platform=row["platform"].strip(), username=row["username"].strip()).first()
                if not obj:
                    obj = Account(platform=row["platform"].strip(), username=row["username"].strip()); db.add(obj)
                obj.employee_id = emp.id if emp else None
                obj.status = row["status"].strip()
                obj.last_login = parse_dt(row.get("last_login"))
                obj.last_login_source = row.get("last_login_source", "csv")
                obj.synced_at = utcnow()
            elif kind in {"entitlements", "activities"}:
                acc = db.query(Account).filter_by(platform=row["platform"].strip(), username=row["username"].strip()).first()
                if not acc:
                    raise ValueError("Unknown account: import accounts first")
                if kind == "entitlements":
                    resource, permission = row["resource"].strip(), row["permission"].strip()
                    obj = db.query(Entitlement).filter_by(account_id=acc.id, resource=resource, permission=permission).first()
                    if not obj:
                        obj = Entitlement(account_id=acc.id, resource=resource, permission=permission); db.add(obj)
                    obj.sensitivity = row["sensitivity"].strip().lower()
                    obj.source = row.get("source", "csv") or "csv"
                    obj.active = row.get("active", "true").strip().lower() != "false"
                    obj.last_used_at = parse_dt(row.get("last_used_at"))
                    obj.evidence_source = (row.get("evidence_source") or None)
                else:
                    obj = Activity(account_id=acc.id, resource=row["resource"].strip(), event_type=row["event_type"].strip(), occurred_at=parse_dt(row["occurred_at"]), source=row["source"].strip())
                    db.add(obj)
                    # Only explicit resource-use events can update entitlement use.
                    if obj.event_type.lower() == "resource_use":
                        for e in db.query(Entitlement).filter_by(account_id=acc.id, resource=obj.resource).all():
                            if not e.last_used_at or e.last_used_at < obj.occurred_at:
                                e.last_used_at = obj.occurred_at
                                e.evidence_source = obj.source
            db.flush()
            count += 1
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(422, f"CSV row {i if rows else 0}: {str(exc)[:250]}")
    return count
