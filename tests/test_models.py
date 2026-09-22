from datetime import datetime

from models import MonitoredUser, ActivityLog, Alert, UserBaseline


def test_monitored_user_activity_relationship(db, sample_user, activity_factory):
    activity_factory(sample_user, activity_type="login")
    activity_factory(sample_user, activity_type="download", data_volume_mb=12.5)

    assert sample_user.activity_logs.count() == 2


def test_activity_log_to_alert_relationship(db, sample_user, activity_factory):
    activity = activity_factory(sample_user, activity_type="download", data_volume_mb=900)
    alert = Alert(
        log_id=activity.log_id,
        user_id=sample_user.user_id,
        alert_type="rule-based",
        risk_score=85.0,
        description="Excessive data download",
        status="open",
        date_generated=datetime.utcnow(),
    )
    db.session.add(alert)
    db.session.commit()

    assert activity.alert.alert_id == alert.alert_id
    assert alert.user.username == "jdoe"


def test_user_baseline_one_to_one(db, sample_user):
    baseline = UserBaseline(
        user_id=sample_user.user_id,
        avg_login_hour=9.5,
        avg_daily_data_volume_mb=42.0,
        std_dev_data_volume=10.0,
        last_updated=datetime.utcnow(),
    )
    db.session.add(baseline)
    db.session.commit()

    assert sample_user.baseline.avg_login_hour == 9.5
