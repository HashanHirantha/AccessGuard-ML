"""Read-only GitHub repo-collaborator inventory. Does not infer user activity."""
import os
import httpx
from urllib.parse import quote
from fastapi import HTTPException
from sqlalchemy.orm import Session
from .models import Account, Entitlement, utcnow

async def sync_github(db: Session):
    org, token = os.getenv("GITHUB_ORG", "").strip(), os.getenv("GITHUB_TOKEN", "").strip()
    if not org or not token:
        raise HTTPException(422, "Configure GITHUB_ORG and GITHUB_TOKEN on the backend")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    count = 0
    try:
        async with httpx.AsyncClient(base_url="https://api.github.com", headers=headers, timeout=20, follow_redirects=False) as client:
            # Fixed maximum scope to avoid accidental organizational-scale ingestion.
            response = await client.get(f"/orgs/{quote(org, safe='')}/repos", params={"per_page": 30, "page": 1, "type": "all"})
            response.raise_for_status()
            repos = response.json()
            for repo in repos:
                if not repo.get("name"):
                    continue
                url = f"/repos/{quote(org, safe='')}/{quote(repo['name'], safe='')}/collaborators"
                response = await client.get(url, params={"per_page": 100, "page": 1, "affiliation": "all"})
                response.raise_for_status()
                for member in response.json():
                    login = member["login"]
                    acc = db.query(Account).filter_by(platform="GitHub", username=login).first()
                    if not acc:
                        acc = Account(platform="GitHub", username=login, employee_id=None, status="active")
                        db.add(acc); db.flush()
                    acc.synced_at = utcnow()
                    role = member.get("role_name", "read")
                    ent = db.query(Entitlement).filter_by(account_id=acc.id, resource=f"github:{repo['name']}", permission=role).first()
                    if not ent:
                        ent = Entitlement(account_id=acc.id, resource=f"github:{repo['name']}", permission=role)
                        db.add(ent)
                    ent.source = "GitHub REST API"
                    ent.sensitivity = "high" if repo.get("private") else "medium"
                    ent.active = True
                    # No last-used timestamp: GitHub collaborator membership is not proof of activity.
                    count += 1
        db.commit()
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        db.rollback()
        raise HTTPException(502, f"GitHub sync failed; check permissions, rate limits, and org name: {str(exc)[:180]}")
    return {"repositories_scanned": len(repos), "entitlements_seen": count, "note": "Read-only; first page of up to 30 repositories and 100 collaborators per repository. Existing records are not revoked. Map accounts using CSV imports."}
