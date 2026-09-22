import io

import pytest

from data_ingestion import import_activity_csv, generate_synthetic_log, IngestionError
from models import MonitoredUser, ActivityLog


CSV_CONTENT = """username,full_name,department,role,activity_type,resource_accessed,data_volume_mb,ip_address,timestamp
jdoe,Jane Doe,Finance,Analyst,login,,,10.0.0.1,2026-01-05 09:00:00
jdoe,Jane Doe,Finance,Analyst,download,finance_reports,25.5,10.0.0.1,2026-01-05 09:15:00
bsmith,Bob Smith,Engineering,Software Engineer,login,,,10.0.0.2,2026-01-05 08:45:00
"""


def test_import_csv_creates_users_and_logs(db):
    summary = import_activity_csv(io.StringIO(CSV_CONTENT))
    assert summary["users_created"] == 2
    assert summary["logs_created"] == 3
    assert MonitoredUser.query.count() == 2
    assert ActivityLog.query.count() == 3


def test_import_csv_missing_required_column_raises(db):
    bad_csv = "username,activity_type\njdoe,login\n"
    with pytest.raises(IngestionError):
        import_activity_csv(io.StringIO(bad_csv))


def test_import_csv_invalid_activity_type_raises(db):
    bad_csv = "username,activity_type,timestamp\njdoe,teleport,2026-01-05 09:00:00\n"
    with pytest.raises(IngestionError):
        import_activity_csv(io.StringIO(bad_csv))


def test_generate_synthetic_log_shape():
    df = generate_synthetic_log(num_users=5, num_days=10, seed=1)
    assert not df.empty
    assert set(["username", "activity_type", "timestamp", "data_volume_mb"]).issubset(df.columns)
    assert df["activity_type"].isin(["login", "file_access", "download", "transfer"]).all()
