import io
from datetime import datetime

from models import Alert


def login(client, username="admin", password="admin123"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def test_login_required_redirects(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert b"Login" in response.data or b"login" in response.data


def test_login_success(client, admin_user):
    response = login(client)
    assert response.status_code == 200
    assert b"Dashboard" in response.data


def test_login_failure_shows_flash(client, admin_user):
    response = client.post(
        "/login", data={"username": "admin", "password": "wrong"}, follow_redirects=True
    )
    assert b"Invalid username or password" in response.data


def test_dashboard_shows_summary_panels(client, admin_user, sample_user, activity_factory):
    login(client)
    activity_factory(sample_user, activity_type="login")
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"Total Users" in response.data
    assert b"Open Alerts" in response.data


def test_csv_upload_flow(client, admin_user):
    login(client)
    csv_content = (
        "username,activity_type,timestamp\n"
        "jdoe,login,2026-01-05 09:00:00\n"
    )
    data = {
        "action": "upload_csv",
        "csv_file": (io.BytesIO(csv_content.encode()), "activity.csv"),
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Imported" in response.data


def test_alert_status_update(client, admin_user, sample_user, activity_factory, db, rule_config):
    login(client)
    activity = activity_factory(sample_user, activity_type="download", data_volume_mb=999)
    alert = Alert(
        log_id=activity.log_id,
        user_id=sample_user.user_id,
        alert_type="rule-based",
        risk_score=90.0,
        description="Excessive data download",
        status="open",
        date_generated=datetime.utcnow(),
    )
    db.session.add(alert)
    db.session.commit()

    response = client.post(
        f"/alerts/{alert.alert_id}", data={"status": "reviewed"}, follow_redirects=True
    )
    assert response.status_code == 200
    updated = db.session.get(Alert, alert.alert_id)
    assert updated.status == "reviewed"
