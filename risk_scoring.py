"""
risk_scoring.py
----------------
Computes composite risk scores and generates alerts, per Section 3.10.3
("Algorithm for Risk Scoring and Alert Generation"):

    BEGIN ComputeRiskScore(activity)
        score = 0
        rule_flags = RuleBasedCheck(activity)
        score += (len(rule_flags) * RULE_WEIGHT)
        IF activity.is_ml_anomalous THEN
            score += (ABS(activity.anomaly_score) * ML_WEIGHT)
        END IF
        score = NORMALIZE(score, 0, 100)
        IF score >= HIGH_RISK_THRESHOLD THEN
            CREATE Alert(activity, score, rule_flags, status='open')
            NOTIFY administrator
        END IF
        RETURN score
    END

run_detection_cycle() is the batch orchestrator referenced in the last
paragraph of Section 3.10: it runs baseline.py, rule_engine.py and
anomaly_detector.py over newly-ingested activity, then calls
compute_risk_score() immediately afterwards "to generate and persist
alerts for administrator review via the dashboard".
"""

from datetime import datetime

from extensions import db
from models import ActivityLog, Alert, MonitoredUser
from rule_engine import get_active_config, rule_based_check
from anomaly_detector import run_anomaly_detection_for_all_users
import baseline as baseline_module

NOTIFICATION_LOG = []  # in-process stand-in for "NOTIFY administrator"


def _normalize(score: float, low: float = 0.0, high: float = 100.0) -> float:
    """NORMALIZE(score, 0, 100) -> clamp into [low, high]."""
    return max(low, min(high, score))


def _notify_administrator(alert: Alert) -> None:
    """
    NOTIFY administrator.

    The dashboard's open-alerts list and summary counters (Section 3.9.2)
    already surface new alerts on next page load, so this stand-in simply
    records the notification; a production deployment would hook this to
    email/Slack/webhook delivery.
    """
    NOTIFICATION_LOG.append(
        {
            "alert_id": alert.alert_id,
            "user_id": alert.user_id,
            "risk_score": alert.risk_score,
            "at": datetime.utcnow().isoformat(),
        }
    )


def compute_risk_score(
    activity: ActivityLog,
    user: MonitoredUser,
    is_ml_anomalous: bool = False,
    anomaly_score: float = 0.0,
    config=None,
) -> float:
    """
    ComputeRiskScore(activity) -> float score in [0, 100].

    Creates and persists an Alert (and flips ActivityLog.is_flagged) when
    the score meets or exceeds HIGH_RISK_THRESHOLD. Does not commit --
    callers batch commits so a whole detection cycle is one transaction.
    """
    if config is None:
        config = get_active_config()

    rule_flags = rule_based_check(activity, user, config)

    score = 0.0
    score += len(rule_flags) * config.rule_weight
    if is_ml_anomalous:
        score += abs(anomaly_score) * config.ml_weight

    score = _normalize(score, 0, 100)

    if score >= config.high_risk_threshold:
        if rule_flags and is_ml_anomalous:
            alert_type = "rule-based+ML-based"
        elif rule_flags:
            alert_type = "rule-based"
        else:
            alert_type = "ML-based"

        description_parts = list(rule_flags)
        if is_ml_anomalous:
            description_parts.append(f"Anomalous vs. behavioural baseline (score={anomaly_score:.3f})")
        description = "; ".join(description_parts) or "Elevated composite risk score"

        alert = Alert(
            log_id=activity.log_id,
            user_id=user.user_id,
            alert_type=alert_type,
            risk_score=score,
            description=description[:255],
            status="open",
            date_generated=datetime.utcnow(),
        )
        db.session.add(alert)
        activity.is_flagged = True
        db.session.flush()  # populate alert.alert_id before notifying
        _notify_administrator(alert)

    return score


def run_detection_cycle(user_ids=None) -> dict:
    """
    Runs one full analysis cycle over the given users (default: everyone):
      1. Recompute behavioural baselines (baseline.py)
      2. Run ML anomaly detection per user (anomaly_detector.py)
      3. Run rule-based checks + composite risk scoring for every activity,
         generating alerts where warranted (this module)

    Mirrors the flow described at the end of Section 3.10: ingestion/
    baseline/rule/anomaly modules run on a scheduled batch basis, and risk
    scoring runs immediately after to persist alerts for the dashboard.

    Returns a small summary dict for display/logging.
    """
    config = get_active_config()

    if user_ids is None:
        user_ids = [u.user_id for u in MonitoredUser.query.all()]

    baseline_module.update_all_baselines(commit=False)

    ml_results = run_anomaly_detection_for_all_users(user_ids)

    activities_scored = 0
    alerts_created_before = Alert.query.count()

    for user in MonitoredUser.query.filter(MonitoredUser.user_id.in_(user_ids)).all():
        activities = ActivityLog.query.filter_by(user_id=user.user_id).all()
        for activity in activities:
            ml_result = ml_results.get(activity.log_id)
            is_ml_anomalous = ml_result.is_anomalous if ml_result else False
            anomaly_score = ml_result.anomaly_score if ml_result else 0.0
            compute_risk_score(
                activity,
                user,
                is_ml_anomalous=is_ml_anomalous,
                anomaly_score=anomaly_score,
                config=config,
            )
            activities_scored += 1

    db.session.commit()

    alerts_created = Alert.query.count() - alerts_created_before
    return {
        "users_processed": len(user_ids),
        "activities_scored": activities_scored,
        "alerts_created": alerts_created,
    }
