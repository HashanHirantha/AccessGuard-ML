# AccessGuard ML Build Guide

English edition | November 4, 2026

## What you will build

Build an ML prototype that combines Linux, Windows, and CSV account inventories with activity logs to prioritize accounts for human access review. Start with a command-line interface and CSV and JSON reports. Once the model works, you can integrate the reports into the existing AccessGuard web application.

| Component | Deliverable |
| --- | --- |
| Inputs | Account inventory, activity events linked to accounts, and source coverage records |
| Processing | Input validation, identity mapping, and features for each account and time window |
| ML | A trained Isolation Forest model with version metadata |
| Output | Review required, No review recommended, or Insufficient evidence |
| Verification | Held-out scenarios, comparisons with baselines, and an error analysis report |

## Build sequence

1. Set up the repository and Python environment.
2. Prepare the Linux and Windows lab and start collecting baseline events.
3. Normalize raw sources to a common schema and verify log coverage.
4. Build historical features and establish rule-based and statistical baselines.
5. Train the model and select a review threshold on validation data.
6. Evaluate on held-out test data and prepare the report and demonstration.

Run the commands on lab machines you are authorized to use. Implement the raw-log parsers and feature builder in Steps 2–7 before running the training example in Step 8.

---

## Step 1. Set up the environment and repository

Use Python, Git, a code editor, a Linux VM, and an authorized Windows machine or VM. Run the VMs together or separately according to your available resources. Use a private or host-only lab network. A local CPU is enough for the initial experiment.

### Windows PowerShell

```powershell
mkdir accessguard-ml
cd accessguard-ml
git init
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install pandas scikit-learn joblib pytest
.\.venv\Scripts\python.exe -m pip freeze > requirements-lock.txt
```

### Linux

```bash
mkdir accessguard-ml
cd accessguard-ml
git init
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install pandas scikit-learn joblib pytest
.venv/bin/python -m pip freeze > requirements-lock.txt
```

Choose one machine as the training environment and use the commands for its shell. The virtual environment isolates your Python dependencies. [G1]

### Project folders

Create `data/raw/`, `data/processed/`, `data/scenarios/`, `models/`, `reports/`, `src/`, `tests/`, and `docs/`. Use `.gitignore` to keep the virtual environment, raw logs, private data, and model artifacts out of Git. Commit schema examples and small sanitized fixtures you have permission to share.

**Completion check.** Import `pandas` and `sklearn` from the virtual environment and verify that Git excludes private logs.

---

## Step 2. Collect the Linux inventory and login logs

Run these commands in the Ubuntu lab VM. They install the collection tools, create two test users, and export the local inventory and its collection time. [G2]

```bash
sudo apt update
sudo apt install openssh-server auditd python3-venv
mkdir -p data/raw
sudo adduser review_alice
sudo adduser review_bob
getent passwd > data/raw/linux-passwd.txt
getent group > data/raw/linux-group.txt
date -u +"%Y-%m-%dT%H:%M:%SZ" > data/raw/linux-collected-at.txt
```

The `getent passwd` export can include both human and system accounts. Keep an explicit allowlist of your lab users. Map each Linux UID and username to its source host. Record business roles in a separate lab mapping file.

### Collect login events

Use the VM IP address from your lab configuration to sign in over SSH as a test user, then sign out. Authenticate with SSH keys or your lab’s configured method and keep credentials out of the code.

```bash
sudo journalctl --since "7 days ago" --until "now" \
  --output=json --no-pager > data/raw/linux-journal.jsonl
```

Depending on the distribution, authentication events may appear in the journal or a file such as `/var/log/auth.log`. Verify that the export contains the SSH or sudo event you generated. [G3]

A journal entry’s `_UID` can identify the sshd or root process that wrote the message. Extract the authenticated account from the source event’s structure or message, then join it to the inventory.

**Completion check.** Find the test login’s username, timestamp, outcome, and source record. Use the exported inventory fields and keep `/etc/shadow` and password hashes outside the export.

---

## Step 3. Collect activity beyond logins

Login events establish that someone signed in. Detect a shift in work activity using attributable process or application events.

### Temporary process auditing on an x86-64 lab VM

Run `uname -m` and verify your lab’s UID allocation. This example covers 64-bit execution and login UIDs of 1000 or greater. Adapt the rule to the architecture and UID policy of your lab. [G4]

```bash
sudo auditctl -l > data/raw/audit-rules-before.txt
sudo auditctl -a always,exit -F arch=b64 -S execve \
  -F 'auid>=1000' -F 'auid!=4294967295' -k accessguard_lab
sudo auditctl -l
sudo ausearch -k accessguard_lab --start today --raw \
  > data/raw/linux-activity.audit
```

After adding the rule, open a fresh SSH session as a lab user, perform a few permitted tasks, and repeat the export. Use `auid` to trace the original login identity. Switching users from a root session can leave the original login identity in the audit record.

### Normalize audit events

An execution can produce multiple records such as `SYSCALL`, `EXECVE`, and `PATH`. Group records by the audit timestamp and serial number so each execution contributes one event.

Maintain a mapping from observed executables or actions to categories such as `network`, `database`, and `administration`. Document how much you can infer from an executable name and include only the sanitized category needed for the report. Keep secrets out of command-line arguments.

**Completion check.** Identify the actor, timestamp, and executable for the test action. To remove the temporary rule, repeat the rule specification with `-d` in place of `-a`.

---

## Step 4. Collect the Windows inventory and events

Use an administrator PowerShell session on the lab machine. The audit subcategory names below are for English Windows. Use `auditpol /list /subcategory:*` to find the names on other language installations. Record the existing audit policy before enabling collection. [G5]

```powershell
New-Item -ItemType Directory -Force data\raw
auditpol /get /category:* > data\raw\audit-policy-before.txt
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
Get-LocalUser | Select-Object Name, SID, Enabled, LastLogon |
  Export-Csv data\raw\windows-users.csv -NoTypeInformation -Encoding utf8
Get-LocalGroupMember -SID 'S-1-5-32-544' |
  Select-Object Name, SID |
  Export-Csv data\raw\windows-admins.csv -NoTypeInformation -Encoding utf8
```

Keep missing `LastLogon` values as unknown. Record local administrator-group membership separately from business roles. Use event 4624 for successful logons, 4625 for failed logons, and 4688 for process creation when that auditing is enabled. [G6] [G7]

```powershell
$filter = @{
  LogName = 'Security'
  Id = 4624, 4625, 4688
  StartTime = (Get-Date).AddDays(-7)
}
Get-WinEvent -FilterHashtable $filter | ForEach-Object {
  [pscustomobject]@{
    SystemId = 'win-lab-01'
    RecordId = $_.RecordId
    EventXml = $_.ToXml()
  } | ConvertTo-Json -Compress
} | Set-Content -Encoding utf8 data\raw\windows-events.jsonl
```

For 4624, use `TargetUserSid` and `TargetUserName` to identify the account that logged in. `SubjectUserSid` can refer to a different process identity. Implement 4688 actor mapping separately according to its event schema. Read CSV or JSON files with `utf-8-sig` if they contain a UTF-8 byte order mark.

**Completion check.** Match the test login to the correct user SID. If the query returns no events, investigate the collection window, audit policy, and permissions before interpreting account activity.

---

## Step 5. Normalize the sources and map identities

Implement `normalize.py` or separate source adapters to produce the files below. Read identifiers as strings and retain references back to the original records. Copy the lab exports to `data/raw/linux/` and `data/raw/windows/` on the training machine. Record the source ID and collection time.

| File | Fields |
| --- | --- |
| `accounts.csv` | system_id, source_account_id, account_name, platform, account_type, role, enabled_status, observed_at |
| `events.jsonl` | system_id, source_account_id, event_time, event_type, outcome, activity_category, source_event_id |
| `coverage.csv` | system_id, start_time, end_time, authentication_ok, activity_ok, collection_ok |
| `scenarios.csv` | case_id, account_key, window_end, expected_state, needs_review, rationale |

Use the pair `(system_id, source_account_id)` as a composite key with two distinct components. Map the Windows SID, Linux UID, or application account ID within its host or application context. Keep accounts with the same username on different systems separate.

### CSV application and Apache sources

An account inventory exported as CSV still needs linked application events for behavior analysis. For Apache, use an access log that records the authenticated remote user through `%u`. Treat requests with a missing authenticated user as unattributed and keep tokens, cookies, and passwords out of the report. [G8]

### Verify source coverage

Record whether auditing was enabled, what interval the export covers, whether collection succeeded, and whether a known test event appeared. Use that evidence to distinguish an observed period with zero events from a gap in collection.

- Quarantine records with malformed timestamps or unknown identities and report their counts.
- Convert Windows XML, Linux journal, and Linux audit timestamps to UTC and retain the original value.
- Use stable source event IDs to deduplicate records when an export is imported again.
- Keep the account inventory as the starting population so accounts with zero events remain in the output.

**Completion check.** Confirm that `alice` on two hosts remains two accounts and that parse and mapping failures appear in the report.

---

## Step 6. Build account features for each time window

Implement `features.py`. Each row represents one account at one assessment time. Retain account identity, `platform`, `account_type`, and `window_end` as metadata. When enough history exists, start with a seven-day baseline followed by a one-day current window.

| Feature | Calculation |
| --- | --- |
| `login_success_1d` | Successful logons in the current window |
| `login_failure_1d` | Failed logons in the current window |
| `activity_events_1d` | Activity events reliably linked to the account |
| `privileged_events_1d` | Privileged events identified using the documented category mapping |
| `login_delta` | Current login count minus the baseline daily mean |
| `activity_delta` | Current activity count minus the baseline daily mean |
| `days_since_last_success` | Elapsed days since the most recent reliable successful event |
| `evidence_ok` | 1 when source coverage, identity mapping, and history meet the requirements. Otherwise 0. |

If the baseline contains 21 successful logins across seven days, the daily mean is 3. With verified coverage and zero logins in the current day, `login_delta = -3`.

Use zero only for a covered period with zero observed events. Set the evidence state to incomplete when a required log source is unavailable. Left-join activity to the inventory to retain accounts with no matching events.

### Prevent leakage

Build each row using only the data available at its assessment time. Keep later events, review outcomes, and scenario labels out of the feature inputs. End the baseline before the current window and check that shared Linux and Windows features represent comparable behavior.

**Completion check.** Reprocess the same raw snapshot and verify identical feature values, an output row for a known account with zero events, and `evidence_ok=0` when required coverage is missing.

---

## Step 7. Separate training, validation, and testing

Start collecting baseline events in week one and build features once enough history is available. Document demonstration windows separately from evaluation windows, especially if a short calendar schedule requires a smaller demo window.

1. **Training** uses earlier reference activity to fit feature transforms and the model.
2. **Validation** uses separate development scenarios to select model settings and the review threshold.
3. **Test** uses a later, untouched period and scenarios for final evaluation.

Assign each assessment record to one split. In chronological splits, construct features from history available at each assessment and remove overlapping windows that would expose future data. Assess monitoring of known accounts and generalization to new accounts separately. [G9]

### Establish the baselines

- **Rules baseline** uses configured inactivity, known privilege changes, and explicit policy triggers.
- **Statistical baseline** measures how far recent activity counts or category mix depart from the account’s historical baseline.

Define the review-worthy scenarios independently of the rules baseline. Agreement with rule-generated labels measures agreement with those rules.

### Record the scenarios

Include stable activity, a previously active account that stops, an observable change in activity category, an authorized privilege change, a new account, and a missing source. Record the expected test state before looking at model results. Keep unknown cases separate from confirmed `needs_review=0` cases.

**Completion check.** Produce `features_train.csv`, `features_validation.csv`, and `features_test.csv`. Document the account and window IDs and dates for each split.

---

## Step 8. Train the Isolation Forest

Save this example as `train.py` after building the feature columns and data splits in Steps 6 and 7. The example trains the initial Linux model. Use a separate Windows artifact once you have sufficient Windows data. Keep identity fields and labels outside the predictors. [G10]

```python
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

cols = [
    "login_success_1d", "login_failure_1d",
    "activity_events_1d", "privileged_events_1d",
    "login_delta", "activity_delta",
]
df = pd.read_csv("data/processed/features_train.csv")
df = df.loc[
    df["evidence_ok"].eq(1) & df["platform"].eq("linux")
    & df["account_type"].eq("human")
].copy()
if df.empty:
    raise ValueError("No eligible Linux training records")
X = df[cols].apply(pd.to_numeric, errors="raise")
if not np.isfinite(X.to_numpy(dtype=float)).all():
    raise ValueError("Required features must be finite")
if X.nunique().max() <= 1:
    raise ValueError("Collect varied baseline activity first")
model = IsolationForest(
    n_estimators=200, contamination="auto",
    random_state=42, n_jobs=-1,
)
model.fit(X)
artifact = {
    "model": model, "features": cols, "platform": "linux",
    "version": "iforest-v1", "training_rows": len(X),
    "sklearn_version": sklearn.__version__,
}
Path("models").mkdir(exist_ok=True)
joblib.dump(artifact, "models/linux-iforest.joblib")
print("Saved trained model", len(X))
```

Run `.\.venv\Scripts\python.exe train.py` in Windows PowerShell or `.venv/bin/python train.py` on Linux.

Use these settings as a starting point. Choose the business review threshold separately on validation data. Record the training date range, feature schema, source hashes, and selected threshold alongside the artifact metadata.

---

## Step 9. Set the review threshold and generate reports

Use this snippet in your scoring module to compute validation scores. Import `joblib` and `pandas as pd`, and load artifacts produced by your trusted pipeline. Before calling the model, verify that eligible rows exist and that required numeric inputs are finite, as in the training script. If there are no eligible rows, report insufficient evidence. [G11]

```python
artifact = joblib.load("models/linux-iforest.joblib")
validation = pd.read_csv("data/processed/features_validation.csv")
eligible = validation["evidence_ok"].eq(1)
eligible &= validation["platform"].eq(artifact["platform"])
eligible &= validation["account_type"].eq("human")
Xv = validation.loc[eligible, artifact["features"]]
validation.loc[eligible, "anomaly_score"] = (
    -artifact["model"].decision_function(Xv)
)
```

A lower scikit-learn decision score indicates more unusual behavior. The minus sign reverses that direction so a higher exported score ranks an account as more unusual. Interpret it as an anomaly ranking. [G10]

### Select the threshold

Compare the flagged count, precision, and recall at several thresholds on validation data. Select a threshold based on reviewer capacity and the cost of missed cases. Save it with the model version in `threshold.json` and keep it fixed during final testing.

### Assign the review state

Apply these decisions in order.

1. **Review required** when a mandatory policy trigger is confirmed. Include any evidence gaps in the same report entry.
2. **Insufficient evidence** when the first condition does not apply and required history, mapping, or source coverage is incomplete.
3. **Review required** when the evidence is adequate and the anomaly score exceeds the threshold.
4. **No review recommended** for the remaining covered accounts.

Export the account key, assessment time, state, anomaly score, policy flags, reason, observed and baseline values, coverage, model version, and source references. A human reviewer decides what action to take on each account.

---

## Step 10. Evaluate the model and test the pipeline

Compare rules alone, the statistical baseline, Isolation Forest, and the hybrid approach on the same test accounts and with the same review capacity. Count policy cases toward the overall workload and report the model’s additional value for behavior-change cases separately.

### Evaluation measures

- **Precision** measures the fraction of flagged cases that warrant review.
- **Recall** measures the fraction of review-worthy cases detected.
- Report average precision, along with precision and recall at the chosen review capacity.
- Record false alerts per 100 assessments, runtime, and memory usage.
- Count total accounts, eligible accounts, insufficient-evidence cases, and source mapping or parsing failures.

Report performance for the eligible subset alongside coverage across the entire dataset. Keep cases with unknown labels separate from evaluation negatives.

### Software checks

| Test | Expected result |
| --- | --- |
| Same username on two hosts | The accounts stay separate. |
| Duplicate source import | Event counts stay the same. |
| Source outage | The output shows a coverage gap. |
| Account with zero events | The account remains in the output. |
| Add an event after the assessment time | Features for the earlier assessment stay the same. |
| Reload the artifact | The same inputs produce the same predictions. |
| Unusual account with no rule trigger | The account is eligible for ML scoring if its evidence is adequate. |
| Model and platform mismatch | The output identifies the unsupported input. |

**Completion check.** Save the test results separately and explain the main false positives and false negatives. Report measured lab performance and document the population and conditions the test covered.

---

## Step 11. Prepare the demonstration and handover

### Demonstration sequence

1. Show the Linux, Windows, and CSV account inventories.
2. Trace an actual lab log record to the correct account.
3. Show how current behavior differs from the baseline.
4. Load the trained artifact and reproduce the scores and review report.
5. Demonstrate normal activity, changed activity, and insufficient evidence.
6. Present the comparison against rules alone and explain the model’s limitations.

Make the CLI workflow reproducible. If time permits, add report import to the existing AccessGuard UI. The dashboard and live inference API are optional extensions.

### Estimated six-week schedule

| Week | Deliverable |
| --- | --- |
| 1 | Confirm the scope, set up the repository and lab, export inventories, and start collecting events. |
| 2 | Implement parsers, identity mapping, and data quality and coverage reports. |
| 3 | Build features, baselines, and the initial model. |
| 4 | Freeze thresholds, run held-out scenarios, and analyze errors. |
| 5 | Complete the CLI, reproducible reports, and end-to-end demonstration. |
| 6 | Fix defects, complete documentation and evaluation, and prepare the handover. |

The estimate assumes 15–20 developer hours per week and timely access to lab resources and data. If baseline history is limited, continue collection and scope your claims to the evidence available by the deadline.

### Handover

Include the README, dependency lock file, schemas, sanitized examples, collection settings, scenario manifest, feature configuration, model artifact with its hash and version, validation threshold, test results, model card, and demo instructions. Run parser, feature, and report tests in GitHub CI using sanitized fixtures.

On the first two days, prepare the two lab machines, create test accounts, and verify that known login and activity events are captured. This lets the baseline history accumulate while you build the pipeline.

---

## Technical references

This guide follows the meeting-aligned English proposal. Use the documentation below to check the commands and their applicability to your OS and software versions. The original guide checked these references on November 3, 2026.

- **G1** [Python virtual environments](https://docs.python.org/3/tutorial/venv.html)
- **G2** [Ubuntu OpenSSH server](https://ubuntu.com/server/docs/how-to/security/openssh-server/)
- **G3** [systemd journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- **G4** [Red Hat Linux auditing and audit rules](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)
- **G5** [Microsoft auditpol set](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set) and [PowerShell LocalAccounts](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts)
- **G6** [Microsoft Event 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624) and [Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- **G7** [Microsoft Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- **G8** [Apache mod_log_config](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)
- **G9** [scikit-learn common pitfalls](https://scikit-learn.org/stable/common_pitfalls.html)
- **G10** [scikit-learn IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- **G11** [scikit-learn model persistence](https://scikit-learn.org/stable/model_persistence.html)
