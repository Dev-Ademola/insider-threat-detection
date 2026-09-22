# Insider Threat Detection System

A Flask + SQLAlchemy implementation of the system described in the
project report ("Design and Implementation of an Insider Threat
Detection System"), Chapter Three. Every module, database table, and
algorithm below is named and structured to match Sections 3.7–3.10 of
that document.

## Architecture (Section 3.7.1)

Three-tier layout, matching Figure 3.1:

```
Data Collection Layer   -> data_ingestion.py   (CSV upload + synthetic demo generator)
Processing/Analysis     -> baseline.py         (behavioural baselines, Table 3.6)
Layer                      rule_engine.py       (Section 3.10.1 rule checks)
                           anomaly_detector.py  (Section 3.10.2 Isolation Forest)
                           risk_scoring.py      (Section 3.10.3 composite score + alerts)
Presentation Layer       -> app.py              (Flask dashboard, Section 3.9)
Database                -> models.py            (Section 3.8 schema, SQLAlchemy ORM)
```

## Database schema (Section 3.8)

Five tables from Table 3.3–3.7, plus one small addition:

| Table | Maps to |
|---|---|
| `MonitoredUser` | Table 3.3 |
| `ActivityLog` | Table 3.4 |
| `Alert` | Table 3.5 |
| `UserBaseline` | Table 3.6 |
| `Admin` | Table 3.7 |
| `RuleConfig` | D4 Rule/Configuration Store (Figure 3.5) — not given an explicit table in 3.8.1, added so thresholds are editable from the "Configure Rules" screen instead of hard-coded |

Default engine is SQLite (`insider_threat.db`), matching the
"MySQL/SQLite" note in the abstract. Point `SQLALCHEMY_DATABASE_URI` at
a MySQL connection string (e.g. via an environment variable read in
`create_app()`) to use MySQL instead — the SQLAlchemy models are
engine-agnostic.

## Use cases implemented (Section 3.7.2 / Figure 3.2)

- Login / Logout (`/login`, `/logout`)
- Upload/Import Activity Logs (`/upload`) — real CSV or the built-in
  synthetic demo generator
- View Dashboard (`/dashboard`) — summary panels, alerts-over-time
  chart, recent high-risk alerts (Figure 3.8)
- View Alerts / Investigate & Update Alert Status (`/alerts`,
  `/alerts/<id>`)
- Per-user risk profile (`/users/<id>`)
- Configure Detection Rules and Thresholds (`/rules`)
- Generate Reports, CSV or PDF (`/reports`)

## Algorithms (Section 3.10)

`rule_engine.py`, `anomaly_detector.py`, and `risk_scoring.py` are
direct implementations of the `RuleBasedCheck`, `AnomalyDetection`, and
`ComputeRiskScore` pseudocode in Sections 3.10.1–3.10.3 — see the
docstring at the top of each file for the pseudocode it mirrors.

## Setup

```bash
pip install -r requirements.txt
python init_db.py --with-demo-data   # creates tables, default admin, loads synthetic
                                      # activity data, and runs one detection cycle
python app.py                        # http://127.0.0.1:5000
```

Default login: `admin` / `admin123` — change this (via `--admin-password`
on `init_db.py`, or directly in the `admin` table) before any real use.

Run `python init_db.py` without `--with-demo-data` for an empty database,
then use the "Load synthetic demo data" button on the Upload page, or
upload your own CSV with columns:

```
username, full_name, department, role, activity_type,
resource_accessed, data_volume_mb, ip_address, timestamp
```

(`sample_data/sample_activity_log.csv` is a small example.) After
importing, click "Run detection cycle" (available on the Upload and
Dashboard pages) to recompute baselines, run the anomaly detector, and
score/alert on the new activity — this mirrors the batch-cycle flow
described at the end of Section 3.10.

## Tests

```bash
pytest
```

28 tests covering models, rule engine, anomaly detector, baseline,
risk scoring, data ingestion, and the Flask routes (login, dashboard,
CSV upload, alert status updates).

## Scope notes carried over from the write-up

Per Sections 1.5/1.6, this is a prototype evaluated on synthetic/sample
data, not production-hardened: no network-level or physical-security
monitoring, limited behavioural indicators (login timing, file access,
data volume), and thresholds that need calibration against a real
organization's baseline traffic before trusting alert volume in
production. See Section 1.6 (Limitations) and the report's
recommendations for further work.
