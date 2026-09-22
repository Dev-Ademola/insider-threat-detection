from datetime import datetime, timedelta

from baseline import compute_user_baseline, update_all_baselines
from models import UserBaseline


def test_baseline_not_computed_with_insufficient_history(db, sample_user, activity_factory):
    activity_factory(sample_user, activity_type="login", timestamp=datetime(2026, 1, 1, 9, 0))
    baseline = compute_user_baseline(sample_user.user_id)
    db.session.commit()
    assert baseline.avg_login_hour is None  # fewer than MIN_LOGIN_EVENTS_FOR_BASELINE


def test_baseline_computed_with_sufficient_history(db, sample_user, activity_factory):
    for day, hour in [(1, 9), (2, 10), (3, 8), (4, 9)]:
        activity_factory(
            sample_user, activity_type="login", timestamp=datetime(2026, 1, day, hour, 0)
        )
        activity_factory(
            sample_user,
            activity_type="download",
            data_volume_mb=10.0,
            timestamp=datetime(2026, 1, day, hour, 30),
        )

    baseline = compute_user_baseline(sample_user.user_id)
    db.session.commit()

    assert baseline.avg_login_hour is not None
    assert 8 <= baseline.avg_login_hour <= 10
    assert baseline.avg_daily_data_volume_mb == 10.0


def test_update_all_baselines_covers_every_user(db, sample_user, activity_factory):
    for day, hour in [(1, 9), (2, 10), (3, 8), (4, 9)]:
        activity_factory(sample_user, activity_type="login", timestamp=datetime(2026, 1, day, hour, 0))

    count = update_all_baselines()
    assert count == 1
    assert UserBaseline.query.filter_by(user_id=sample_user.user_id).first() is not None
