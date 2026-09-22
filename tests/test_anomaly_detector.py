from datetime import datetime, timedelta

from anomaly_detector import run_anomaly_detection, MIN_SAMPLES_FOR_ML


def test_insufficient_history_returns_empty(db, sample_user, activity_factory):
    for i in range(3):
        activity_factory(
            sample_user, activity_type="login", timestamp=datetime(2026, 1, 1 + i, 9, 0)
        )
    results = run_anomaly_detection(sample_user.user_id)
    assert results == []


def test_detects_volume_outlier_with_enough_history(db, sample_user, activity_factory):
    base = datetime(2026, 1, 1, 9, 0)
    # Normal daily downloads around ~10-20MB
    for i in range(20):
        activity_factory(
            sample_user,
            activity_type="download",
            data_volume_mb=15.0 + (i % 3),
            timestamp=base + timedelta(days=i),
        )
    # One wildly larger outlier
    outlier = activity_factory(
        sample_user,
        activity_type="download",
        data_volume_mb=5000.0,
        timestamp=base + timedelta(days=25),
    )

    results = run_anomaly_detection(sample_user.user_id)
    assert len(results) >= MIN_SAMPLES_FOR_ML

    flagged_log_ids = {r.log_id for r in results if r.is_anomalous}
    assert outlier.log_id in flagged_log_ids
