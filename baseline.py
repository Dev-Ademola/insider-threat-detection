"""
baseline.py
-----------
Computes and updates each monitored user's behavioural baseline
(UserBaseline table, Section 3.8.1 / Table 3.6), used both as an input to
the machine-learning anomaly detector (anomaly_detector.py) and, in a
simplified form, as a human-readable reference point on the per-user risk
profile page (Section 3.9.2).

A "baseline" here is the pair of Section-3.8.1 fields:
    avg_login_hour             - mean hour-of-day of the user's login events
    avg_daily_data_volume_mb   - mean of (sum of data_volume_mb per day)
    std_dev_data_volume        - standard deviation of that daily total

recomputed from the full available ActivityLog history for the user each
time it is run, per Section 3.7.3's flowchart step "Update Baseline".
"""

from datetime import datetime

import pandas as pd

from extensions import db
from models import ActivityLog, MonitoredUser, UserBaseline

MIN_LOGIN_EVENTS_FOR_BASELINE = 3
MIN_DAYS_FOR_VOLUME_BASELINE = 3


def _activity_log_to_frame(user_id: int) -> pd.DataFrame:
    rows = ActivityLog.query.filter_by(user_id=user_id).all()
    if not rows:
        return pd.DataFrame(columns=["activity_type", "data_volume_mb", "timestamp"])
    return pd.DataFrame(
        [
            {
                "activity_type": r.activity_type,
                "data_volume_mb": r.data_volume_mb or 0.0,
                "timestamp": r.timestamp,
            }
            for r in rows
        ]
    )


def compute_user_baseline(user_id: int) -> UserBaseline:
    """
    Recompute and persist the UserBaseline row for a single user from
    their full ActivityLog history. Returns the (created or updated)
    UserBaseline instance. Does not commit -- callers batch commits.
    """
    df = _activity_log_to_frame(user_id)

    avg_login_hour = None
    logins = df[df["activity_type"] == "login"]
    if len(logins) >= MIN_LOGIN_EVENTS_FOR_BASELINE:
        avg_login_hour = float(logins["timestamp"].dt.hour.mean())

    avg_daily_data_volume_mb = None
    std_dev_data_volume = None
    if not df.empty:
        daily_totals = df.assign(day=df["timestamp"].dt.date).groupby("day")["data_volume_mb"].sum()
        if len(daily_totals) >= MIN_DAYS_FOR_VOLUME_BASELINE:
            avg_daily_data_volume_mb = float(daily_totals.mean())
            std_dev_data_volume = float(daily_totals.std(ddof=0)) if len(daily_totals) > 1 else 0.0

    baseline = UserBaseline.query.filter_by(user_id=user_id).first()
    if baseline is None:
        baseline = UserBaseline(user_id=user_id)
        db.session.add(baseline)

    baseline.avg_login_hour = avg_login_hour
    baseline.avg_daily_data_volume_mb = avg_daily_data_volume_mb
    baseline.std_dev_data_volume = std_dev_data_volume
    baseline.last_updated = datetime.utcnow()

    return baseline


def update_all_baselines(commit: bool = True) -> int:
    """Recompute baselines for every MonitoredUser. Returns count updated."""
    user_ids = [u.user_id for u in MonitoredUser.query.all()]
    for user_id in user_ids:
        compute_user_baseline(user_id)
    if commit:
        db.session.commit()
    return len(user_ids)
