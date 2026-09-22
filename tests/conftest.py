import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from extensions import db as _db
from models import Admin, MonitoredUser, ActivityLog, RuleConfig
from werkzeug.security import generate_password_hash


@pytest.fixture()
def app():
    app = create_app(database_uri="sqlite:///:memory:")
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def rule_config(db):
    config = RuleConfig(
        login_start_hour=6,
        login_end_hour=20,
        max_download_mb=500,
        restricted_resources_json=json.dumps({"payroll_db": ["HR", "Finance"]}),
        rule_weight=20,
        ml_weight=15,
        high_risk_threshold=60,
    )
    db.session.add(config)
    db.session.commit()
    return config


@pytest.fixture()
def admin_user(db):
    admin = Admin(
        admin_username="admin",
        password_hash=generate_password_hash("admin123"),
        email="admin@example.com",
    )
    db.session.add(admin)
    db.session.commit()
    return admin


@pytest.fixture()
def sample_user(db):
    user = MonitoredUser(
        full_name="Jane Doe",
        username="jdoe",
        department="Finance",
        role="Analyst",
        date_created=datetime.utcnow(),
    )
    db.session.add(user)
    db.session.commit()
    return user


def make_activity(db, user, **overrides):
    defaults = dict(
        user_id=user.user_id,
        activity_type="login",
        resource_accessed=None,
        data_volume_mb=None,
        ip_address="10.0.0.5",
        timestamp=datetime.utcnow(),
        is_flagged=False,
    )
    defaults.update(overrides)
    activity = ActivityLog(**defaults)
    db.session.add(activity)
    db.session.commit()
    return activity


@pytest.fixture()
def activity_factory(db):
    def _factory(user, **overrides):
        return make_activity(db, user, **overrides)
    return _factory
