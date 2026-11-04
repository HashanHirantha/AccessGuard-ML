# Optional 7-day delivery guide — three-person team

This schedule is a suggested way to present and extend the supplied academic MVP. It is not an estimate of production IAM readiness.

| Day | Member A — data / logs / identity | Member B — AI / risk analysis | Member C — API / workflow / frontend | Team handoff |
|---|---|---|---|---|
| 1 | Define employee/account/entitlement CSV schemas and synthetic test cases | Define policy-risk labels and testable hypotheses | Run Docker stack, verify seeded login / API | Shared API contract and test data |
| 2 | Test Windows, Linux, and GitHub inventory examples; map identities | Validate inactivity evidence rules vs missing data | Validate JWT and role-based endpoint protection | Three data sources documented |
| 3 | Import CSVs, test upsert rules and identity mapping | Evaluate risk score weights on known risky cases | Test React inventory and detail views | Risk scenarios reproduced end-to-end |
| 4 | Verify GitHub connector read-only scope and completeness limitations | Add manually labeled positive/negative test cases for precision/recall | Review workflow and audit export demonstrations | Reviewer walkthrough |
| 5 | Validate activity `resource_use` evidence and stale records | Measure false positives of policy vs Isolation Forest flags | Ensure simulated revocation cannot mutate source access | Safe remediation demo |
| 6 | Prepare provenance, sample-data dictionary and privacy notes | Chart metrics; write limitations and reproducibility notes | Write screenshots, workflow diagrams, test report | Integrated review / defect fix |
| 7 | Demonstrate import and identity mapping | Explain anomaly detection and risk score | Present role-based decisions, simulated remediation, CSV evidence | Final recorded demo and submission |

## Clear responsibilities

- **Member A:** `backend/app/importers.py`, `backend/app/github_connector.py`, normalized identity data, sample CSVs, source validation.
- **Member B:** `backend/app/risk.py`, risk policy, anomaly detection, scoring evaluation and research explanation.
- **Member C:** `backend/app/main.py`, `backend/app/security.py`, `frontend/`, workflows, dashboards, test execution and packaging.

Everyone works against the agreed schema and endpoint names; avoid independent database schema changes without a short joint review. Use feature branches, pull requests, and one daily integration run.

## Suggested demo script

1. Show EMP-2042 Finance identity with `dev:production-db` administrator access.
2. Explain why the score is elevated and distinguish recent *account login* from last verified *resource use*.
3. Generate a review campaign, sign in as the reviewer, approve potential revocation with a written reason.
4. Sign in as admin, simulate the revocation, show that actual upstream permission is unchanged.
5. Show the audit event, compliance CSV, and `/api/metrics` values.

## Project evaluation checklist

- [ ] Docker application starts and seeded users can log in.
- [ ] Reviewer cannot import CSV, recompute risk, or simulate removal.
- [ ] An unknown last-use timestamp never produces a false claim of inactivity.
- [ ] High-risk unauthorized cross-department permission is surfaced with an explanation.
- [ ] Duplicate review decision returns an error.
- [ ] Real source entitlement remains active after simulation.
- [ ] Audit events include reviewer, rationale, timestamp, action, and affected entitlement.
- [ ] API and workflow limitations are described accurately.
