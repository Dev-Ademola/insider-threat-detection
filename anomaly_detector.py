"""
anomaly_detector.py
--------------------
Implements the machine-learning anomaly detection algorithm described in
Section 3.10.2 ("Algorithm for Anomaly-Based Detection (Isolation
Forest)"):

    BEGIN AnomalyDetection(user_id)
        data = FETCH historical activity features FOR user_id
               (login_hour, data_volume_mb, num_file_accesses, ...)
        model = IsolationForest(contamination = 0.05)
        model.FIT(data)
        FOR EACH new_activity OF user_id:
            score = model.decision_function(new_activity.features)
            IF model.predict(new_activity.features) == -1 THEN
                FLAG new_activity AS anomalous WITH anomaly_score = score
        END FOR
    END

Per Section 3.10, this module is "typically invoked on a scheduled
(batch) basis" -- run_anomaly_detection() below fits a fresh model per
user on that user's own history and scores that same history, which is
the batch-mode reading of the pseudocode used throughout this project.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from models import ActivityLog

CONTAMINATION = 0.05
MIN_SAMPLES_FOR_ML = 10  # below this, there isn't enough history to fit a model
FEATURE_COLUMNS = ["login_hour", "data_volume_mb", "num_file_accesses"]


@dataclass
class AnomalyResult:
    log_id: int
    is_anomalous: bool
    anomaly_score: float


def _build_feature_frame(user_id: int) -> pd.DataFrame:
    """
    FETCH historical activity features FOR user_id
    (login_hour, data_volume_mb, num_file_accesses, ...)

    - login_hour: hour-of-day of the activity (0-23)
    - data_volume_mb: volume for that activity (0 if not applicable)
    - num_file_accesses: count of file_access/download/transfer events by
      this user on the same calendar day, giving each activity context
      about how "busy" that day was for the user
    """
    rows = ActivityLog.query.filter_by(user_id=user_id).order_by(ActivityLog.timestamp).all()
    if not rows:
        return pd.DataFrame(columns=["log_id", *FEATURE_COLUMNS])

    df = pd.DataFrame(
        [
            {
                "log_id": r.log_id,
                "login_hour": r.timestamp.hour,
                "data_volume_mb": r.data_volume_mb or 0.0,
                "day": r.timestamp.date(),
                "activity_type": r.activity_type,
            }
            for r in rows
        ]
    )
    file_like = df["activity_type"].isin(["file_access", "download", "transfer"])
    daily_counts = df[file_like].groupby("day").size().rename("num_file_accesses")
    df = df.join(daily_counts, on="day")
    df["num_file_accesses"] = df["num_file_accesses"].fillna(0)

    return df[["log_id", *FEATURE_COLUMNS]]


def run_anomaly_detection(user_id: int) -> list:
    """
    AnomalyDetection(user_id) -> list[AnomalyResult], one per ActivityLog
    row for this user. Returns an empty list if there isn't enough
    history yet (MIN_SAMPLES_FOR_ML) to fit a meaningful model.
    """
    feats = _build_feature_frame(user_id)
    if len(feats) < MIN_SAMPLES_FOR_ML:
        return []

    data = feats[FEATURE_COLUMNS].values
    log_ids = feats["log_id"].values

    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(data)

    scores = model.decision_function(data)  # higher = more normal, lower/negative = more anomalous
    predictions = model.predict(data)  # -1 = anomaly, 1 = normal

    results = []
    for log_id, score, pred in zip(log_ids, scores, predictions):
        results.append(
            AnomalyResult(
                log_id=int(log_id),
                is_anomalous=bool(pred == -1),
                anomaly_score=float(score),
            )
        )
    return results


def run_anomaly_detection_for_all_users(user_ids) -> dict:
    """Convenience wrapper: {log_id: AnomalyResult} across many users."""
    combined = {}
    for user_id in user_ids:
        for result in run_anomaly_detection(user_id):
            combined[result.log_id] = result
    return combined
