import os
from uuid import uuid4
os.environ["JWT_SECRET"] = "test-token-secret-should-be-very-long-and-not-production"
os.environ["SEED_DEMO"] = "true"
os.environ["DEMO_ADMIN_PASSWORD"] = "test-admin-password"
os.environ["DEMO_REVIEWER_PASSWORD"] = "test-reviewer-password"
os.environ["DATABASE_URL"] = f"sqlite:////tmp/access-governance-{uuid4().hex}.db"

from fastapi.testclient import TestClient
from app.main import app

def auth(c, username, password):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

def test_end_to_end_approval_and_safe_remediation():
    with TestClient(app) as client:
        admin = auth(client, "admin", "test-admin-password")
        reviewer = auth(client, "reviewer", "test-reviewer-password")
        overview = client.get("/api/overview", headers=admin)
        assert overview.status_code == 200
        assert overview.json()["high_risk"] > 0
        result = client.post("/api/reviews/create", json={"risk_levels": ["high"]}, headers=admin)
        assert result.json()["created"] > 0
        reviews = client.get("/api/reviews", headers=reviewer).json()
        assert reviews
        chosen = reviews[0]
        first_id = chosen["id"]
        assert client.post(f"/api/reviews/{first_id}/decision", json={"decision": "revoke", "reason": "Approved after evidence review"}, headers=reviewer).status_code == 200
        assert client.post(f"/api/reviews/{first_id}/decision", json={"decision": "revoke", "reason": "Repeat attempt"}, headers=reviewer).status_code == 409
        assert client.post(f"/api/reviews/{first_id}/simulate", headers=reviewer).status_code == 403
        simulated = client.post(f"/api/reviews/{first_id}/simulate", headers=admin)
        assert simulated.status_code == 200
        assert simulated.json()["upstream_changed"] is False
        ent = next(x for x in client.get("/api/entitlements", headers=admin).json() if x["id"] == chosen["entitlement_id"])
        assert ent["active"] is True
        assert client.get("/api/audit", headers=admin).status_code == 200
        assert client.get("/api/export/reviews.csv", headers=admin).status_code == 200

def test_rbac_and_inactivity_evidence():
    with TestClient(app) as client:
        reviewer = auth(client, "reviewer", "test-reviewer-password")
        assert client.post("/api/risk/recompute", headers=reviewer).status_code == 403
        admin = auth(client, "admin", "test-admin-password")
        entitlements = client.get("/api/entitlements", headers=admin).json()
        no_evidence = [e for e in entitlements if e["last_used_at"] is None]
        assert no_evidence
        assert all(any("unavailable" in reason for reason in e["reasons"]) for e in no_evidence)

def test_csv_import_resource_use_vs_login_event():
    with TestClient(app) as client:
        admin = auth(client, "admin", "test-admin-password")
        reviewer = auth(client, "reviewer", "test-reviewer-password")
        base = f"audit-{uuid4().hex[:8]}"
        employees_csv = f"code,name,email,department,job_title,status,manager_username\n{base},CSV Test User,{base}@example.test,Finance,Analyst,active,reviewer\n"
        accounts_csv = f"platform,username,employee_code,status,last_login,last_login_source\nLinux,{base},{base},active,2026-11-01T00:00:00Z,test\n"
        ent_csv = f"platform,username,resource,permission,sensitivity,source,active,last_used_at,evidence_source\nLinux,{base},dev:critical-db,admin,critical,test,true,,\n"
        event_login = f"platform,username,resource,event_type,occurred_at,source\nLinux,{base},dev:critical-db,login,2026-11-02T00:00:00Z,test-source\n"
        event_use = f"platform,username,resource,event_type,occurred_at,source\nLinux,{base},dev:critical-db,resource_use,2026-11-02T00:00:00Z,test-source\n"
        assert client.post("/api/integrations/import/employees", headers=reviewer, files={"file": ("employees.csv", employees_csv, "text/csv")}).status_code == 403
        for kind, data in [("employees", employees_csv), ("accounts", accounts_csv), ("entitlements", ent_csv), ("activities", event_login)]:
            res = client.post(f"/api/integrations/import/{kind}", headers=admin, files={"file": (f"{kind}.csv", data, "text/csv")})
            assert res.status_code == 200, res.text
        ent = next(x for x in client.get("/api/entitlements", headers=admin).json() if x["account_username"] == base)
        assert ent["last_used_at"] is None
        assert "unavailable" in " ".join(ent["reasons"])
        res = client.post("/api/integrations/import/activities", headers=admin, files={"file": ("activities.csv", event_use, "text/csv")})
        assert res.status_code == 200, res.text
        ent2 = next(x for x in client.get("/api/entitlements", headers=admin).json() if x["account_username"] == base)
        assert ent2["last_used_at"] is not None
        assert ent2["evidence_source"] == "test-source"
