"""
data_ingestion.py
------------------
Handles the import and normalization of activity-log data (Section 3.10,
module list), for both of the input paths described in Section 3.9.1:

  (i)  bulk CSV upload of real/exported activity logs, and
  (ii) the system's data-generation module, used to simulate activity for
       testing purposes, since Section 1.5/1.6 scope the system as a
       prototype evaluated on synthetic data ("given the sensitivity and
       unavailability of real organizational insider-threat data").

Expected CSV columns (case-insensitive, extra columns ignored):
    username, full_name, department, role,
    activity_type, resource_accessed, data_volume_mb, ip_address, timestamp

Only `username` and `activity_type`/`timestamp` are strictly required;
missing full_name/department/role default to placeholder values and can
be edited later, and a MonitoredUser row is created automatically the
first time a username is seen.
"""

import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from extensions import db
from models import ActivityLog, MonitoredUser

REQUIRED_COLUMNS = {"username", "activity_type", "timestamp"}
ACTIVITY_TYPES = ["login", "file_access", "download", "transfer"]

DEPARTMENTS = ["Finance", "HR", "Engineering", "Sales", "IT", "Legal"]
ROLES_BY_DEPARTMENT = {
    "Finance": ["Analyst", "Accountant", "Manager"],
    "HR": ["Recruiter", "HR Specialist", "Manager"],
    "Engineering": ["Software Engineer", "DevOps Engineer", "Manager"],
    "Sales": ["Sales Rep", "Account Manager", "Manager"],
    "IT": ["SysAdmin", "Support Technician", "Manager"],
    "Legal": ["Paralegal", "Counsel", "Manager"],
}
RESOURCES = [
    "shared_drive", "crm_system", "payroll_db", "source_code_repo",
    "customer_records", "email_gateway", "hr_portal", "finance_reports",
]


class IngestionError(ValueError):
    pass


def get_or_create_user(username: str, full_name: str = None, department: str = None, role: str = None) -> MonitoredUser:
    user = MonitoredUser.query.filter_by(username=username).first()
    if user is not None:
        return user
    user = MonitoredUser(
        username=username,
        full_name=full_name or username.replace(".", " ").title(),
        department=department or random.choice(DEPARTMENTS),
        role=role or "Staff",
        date_created=datetime.utcnow(),
    )
    db.session.add(user)
    db.session.flush()  # assign user_id without a full commit
    return user


def _normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={c: c.strip().lower() for c in df.columns})
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise IngestionError(f"CSV is missing required column(s): {', '.join(sorted(missing))}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise IngestionError("One or more rows have an unparseable 'timestamp' value.")

    if "data_volume_mb" in df.columns:
        df["data_volume_mb"] = pd.to_numeric(df["data_volume_mb"], errors="coerce")
    else:
        df["data_volume_mb"] = np.nan

    for col in ("full_name", "department", "role", "resource_accessed", "ip_address"):
        if col not in df.columns:
            df[col] = None

    df["activity_type"] = df["activity_type"].str.strip().str.lower()
    invalid_types = set(df["activity_type"].unique()) - set(ACTIVITY_TYPES)
    if invalid_types:
        raise IngestionError(
            f"Unrecognized activity_type value(s): {', '.join(sorted(invalid_types))}. "
            f"Expected one of: {', '.join(ACTIVITY_TYPES)}."
        )

    return df


def _ingest_dataframe(df: pd.DataFrame) -> dict:
    """Shared ingestion path for both CSV upload and the synthetic generator."""
    df = _normalize_dataframe(df)

    users_created = 0
    logs_created = 0
    known_usernames = set(u.username for u in MonitoredUser.query.all())

    for username, group in df.groupby("username"):
        first_row = group.iloc[0]
        if username not in known_usernames:
            get_or_create_user(
                username,
                full_name=first_row.get("full_name"),
                department=first_row.get("department"),
                role=first_row.get("role"),
            )
            known_usernames.add(username)
            users_created += 1

        user = MonitoredUser.query.filter_by(username=username).first()

        for _, row in group.iterrows():
            volume = row["data_volume_mb"]
            log = ActivityLog(
                user_id=user.user_id,
                activity_type=row["activity_type"],
                resource_accessed=(row["resource_accessed"] or None),
                data_volume_mb=None if pd.isna(volume) else float(volume),
                ip_address=(row["ip_address"] or None),
                timestamp=row["timestamp"].to_pydatetime(),
                is_flagged=False,
            )
            db.session.add(log)
            logs_created += 1

    db.session.commit()
    return {"users_created": users_created, "logs_created": logs_created}


def import_activity_csv(filepath_or_buffer) -> dict:
    """
    Import and normalize activity-log data from a CSV file (path or
    file-like object, e.g. a Flask upload's .stream), per Section 3.9.1.
    """
    df = pd.read_csv(filepath_or_buffer)
    return _ingest_dataframe(df)


# ---------------------------------------------------------------------------
# Synthetic data generator (Section 1.5/1.6/3.9.1: prototype evaluated on
# simulated activity logs). Seeds a handful of classic insider-threat
# patterns so the rule engine and Isolation Forest model both have real
# signal to find in a fresh demo database.
# ---------------------------------------------------------------------------

def generate_synthetic_log(num_users: int = 25, num_days: int = 45, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)

    users = []
    for i in range(num_users):
        dept = rng.choice(DEPARTMENTS)
        role = rng.choice(ROLES_BY_DEPARTMENT[dept])
        users.append(
            {
                "username": f"user{i+1:03d}",
                "full_name": f"Employee {i+1:03d}",
                "department": dept,
                "role": role,
            }
        )

    # Seed 3 users with insider-threat-like patterns
    anomalous_users = rng.sample(range(num_users), k=min(3, num_users))
    scenarios = ["exfil_before_offboarding", "disgruntled_off_hours", "gradual_hoarding"]

    start_date = datetime.utcnow() - timedelta(days=num_days)
    rows = []

    for idx, user in enumerate(users):
        scenario = None
        if idx in anomalous_users:
            scenario = scenarios[anomalous_users.index(idx) % len(scenarios)]

        for day_offset in range(num_days):
            day = start_date + timedelta(days=day_offset)
            if day.weekday() >= 5 and scenario != "disgruntled_off_hours" and rng.random() > 0.15:
                continue  # most users mostly quiet on weekends

            # Normal login
            login_hour = int(np_rng.normal(9, 1))
            login_hour = max(0, min(23, login_hour))
            if scenario == "disgruntled_off_hours" and rng.random() < 0.6:
                login_hour = rng.choice([0, 1, 2, 22, 23])

            rows.append(
                {
                    **user,
                    "activity_type": "login",
                    "resource_accessed": None,
                    "data_volume_mb": None,
                    "ip_address": f"10.0.{rng.randint(0,20)}.{rng.randint(2,254)}",
                    "timestamp": day.replace(hour=login_hour, minute=rng.randint(0, 59)),
                }
            )

            # File access / download activity
            num_events = rng.randint(1, 4)
            near_end = day_offset > num_days - 10
            for _ in range(num_events):
                volume = abs(np_rng.normal(20, 15))
                if scenario == "exfil_before_offboarding" and near_end:
                    volume = abs(np_rng.normal(600, 200))
                elif scenario == "gradual_hoarding":
                    volume = abs(np_rng.normal(15 + day_offset * 3, 10))

                activity_type = rng.choice(["file_access", "download", "transfer"])
                resource = rng.choice(RESOURCES)
                if user["department"] not in ("Finance", "HR") and resource in ("payroll_db",):
                    resource = "shared_drive"

                hour = login_hour + rng.randint(0, 6)
                rows.append(
                    {
                        **user,
                        "activity_type": activity_type,
                        "resource_accessed": resource,
                        "data_volume_mb": round(float(volume), 2),
                        "ip_address": f"10.0.{rng.randint(0,20)}.{rng.randint(2,254)}",
                        "timestamp": day.replace(hour=min(hour, 23), minute=rng.randint(0, 59)),
                    }
                )

    df = pd.DataFrame(rows)
    return df.sort_values("timestamp").reset_index(drop=True)


def load_synthetic_data_into_db(num_users: int = 25, num_days: int = 45, seed: int = 42) -> dict:
    """Generate synthetic activity data and ingest it via the same path as a CSV upload."""
    df = generate_synthetic_log(num_users=num_users, num_days=num_days, seed=seed)
    return _ingest_dataframe(df)
