from datetime import datetime

from risk_scoring import compute_risk_score, run_detection_cycle
from models import Alert


def test_low_risk_activity_produces_no_alert(db, sample_user, activity_factory, rule_config):
    activity = activity_factory(
        sample_user, activity_type="login", timestamp=datetime(2026, 1, 5, 10, 0)
    )
    score = compute_risk_score(activity, sample_user, config=rule_config)
    db.session.commit()

    assert score == 0.0
    assert Alert.query.count() == 0
    assert activity.is_flagged is False


def test_high_risk_activity_creates_alert(db, sample_user, activity_factory, rule_config):
    sample_user.role = "Software Engineer"
    activity = activity_factory(
        sample_user,
        activity_type="download",
        resource_accessed="payroll_db",
        data_volume_mb=1000,
        timestamp=datetime(2026, 1, 5, 2, 0),
    )
    score = compute_risk_score(activity, sample_user, config=rule_config)
    db.session.commit()

    assert score >= rule_config.high_risk_threshold
    assert Alert.query.count() == 1
    assert activity.is_flagged is True

    alert = Alert.query.first()
    assert alert.log_id == activity.log_id
    assert "After-hours access" in alert.description


def test_ml_anomaly_contributes_to_score(db, sample_user, activity_factory, rule_config):
    activity = activity_factory(
        sample_user, activity_type="download", data_volume_mb=20, timestamp=datetime(2026, 1, 5, 10, 0)
    )
    score_without_ml = compute_risk_score(activity, sample_user, is_ml_anomalous=False, config=rule_config)
    score_with_ml = compute_risk_score(
        activity, sample_user, is_ml_anomalous=True, anomaly_score=-0.3, config=rule_config
    )
    assert score_with_ml > score_without_ml


def test_run_detection_cycle_end_to_end(db, sample_user, activity_factory, rule_config):
    base = datetime(2026, 1, 1, 9, 0)
    from datetime import timedelta
    for i in range(15):
        activity_factory(
            sample_user, activity_type="login", timestamp=base + timedelta(days=i)
        )
        activity_factory(
            sample_user,
            activity_type="download",
            data_volume_mb=10.0,
            timestamp=base + timedelta(days=i, hours=1),
        )

    summary = run_detection_cycle()
    assert summary["users_processed"] == 1
    assert summary["activities_scored"] == 30
