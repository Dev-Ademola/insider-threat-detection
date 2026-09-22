"""
models.py
---------
SQLAlchemy ORM classes defining the database schema described in
Section 3.8 (Database Design) of the project report:

    Admin            <- Table 3.7: Admin (System User) Table Structure
    MonitoredUser     <- Table 3.3: MonitoredUser Table Structure
    ActivityLog       <- Table 3.4: ActivityLog Table Structure
    Alert             <- Table 3.5: Alert Table Structure
    UserBaseline      <- Table 3.6: UserBaseline Table Structure

Relationships (Figure 3.6, ERD):
    MonitoredUser (1) ---< (M) ActivityLog
    ActivityLog   (1) ---< (0..1) Alert
    MonitoredUser (1) --- (1) UserBaseline

RuleConfig is a small addition beyond the five tables listed in 3.8.1: it
backs the "D4 Rule/Configuration Store" shown in the Level-1 DFD
(Figure 3.5) and the "Configure Detection Rules and Thresholds" use case
(Figure 3.2), which the write-up describes but does not give an explicit
table structure for. A single-row table is used since the system, as
scoped, supports one organization-wide policy set.
"""

from datetime import datetime

from flask_login import UserMixin

from extensions import db


class Admin(UserMixin, db.Model):
    """Table 3.7: Admin (System User) Table Structure."""

    __tablename__ = "admin"

    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    # Flask-Login expects a string id(); admin_id is an int primary key.
    def get_id(self):
        return str(self.admin_id)


class MonitoredUser(db.Model):
    """Table 3.3: MonitoredUser Table Structure."""

    __tablename__ = "monitored_user"

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    department = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    activity_logs = db.relationship(
        "ActivityLog", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    alerts = db.relationship(
        "Alert", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    baseline = db.relationship(
        "UserBaseline",
        backref="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<MonitoredUser {self.username} ({self.role}/{self.department})>"


class ActivityLog(db.Model):
    """Table 3.4: ActivityLog Table Structure."""

    __tablename__ = "activity_log"

    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("monitored_user.user_id"), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # login, file_access, download, transfer
    resource_accessed = db.Column(db.String(150), nullable=True)
    data_volume_mb = db.Column(db.Float, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    is_flagged = db.Column(db.Boolean, nullable=False, default=False)

    alert = db.relationship("Alert", backref="activity", uselist=False)

    def __repr__(self):
        return f"<ActivityLog {self.log_id} user={self.user_id} {self.activity_type}>"


class Alert(db.Model):
    """Table 3.5: Alert Table Structure."""

    __tablename__ = "alert"

    alert_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    log_id = db.Column(db.Integer, db.ForeignKey("activity_log.log_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("monitored_user.user_id"), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)  # 'rule-based' or 'ML-based'
    risk_score = db.Column(db.Float, nullable=False)  # 0-100
    description = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")  # open, reviewed, false_positive, escalated
    date_generated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Alert {self.alert_id} user={self.user_id} score={self.risk_score} status={self.status}>"


class UserBaseline(db.Model):
    """Table 3.6: UserBaseline Table Structure."""

    __tablename__ = "user_baseline"

    baseline_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("monitored_user.user_id"), unique=True, nullable=False
    )
    avg_login_hour = db.Column(db.Float, nullable=True)
    avg_daily_data_volume_mb = db.Column(db.Float, nullable=True)
    std_dev_data_volume = db.Column(db.Float, nullable=True)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<UserBaseline user={self.user_id} avg_hour={self.avg_login_hour}>"


class RuleConfig(db.Model):
    """
    Backs the D4 Rule/Configuration Store (Figure 3.5) and the
    'Configure Detection Rules and Thresholds' use case (Figure 3.2).

    A single row holds the organization-wide policy values referenced in
    the rule-based and risk-scoring pseudocode of Section 3.10
    (ORG_MAX_DOWNLOAD_MB, RULE_WEIGHT, ML_WEIGHT, HIGH_RISK_THRESHOLD),
    plus the after-hours window and the restricted-resource -> authorized
    role map used by 'Unauthorized resource access'.
    """

    __tablename__ = "rule_config"

    config_id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # After-hours window, per Section 3.10.1 ("hour < 6 OR hour > 20")
    login_start_hour = db.Column(db.Integer, nullable=False, default=6)
    login_end_hour = db.Column(db.Integer, nullable=False, default=20)

    # ORG_MAX_DOWNLOAD_MB
    max_download_mb = db.Column(db.Float, nullable=False, default=500.0)

    # RESTRICTED_RESOURCES -> authorized roles, stored as JSON text,
    # e.g. {"payroll_db": ["HR", "Finance"], "source_code_repo": ["Engineering"]}
    restricted_resources_json = db.Column(db.Text, nullable=False, default="{}")

    # RULE_WEIGHT / ML_WEIGHT / HIGH_RISK_THRESHOLD (Section 3.10.3).
    # ML_WEIGHT is larger than RULE_WEIGHT because IsolationForest's
    # decision_function() typically returns small magnitudes (roughly
    # 0.02-0.3 for this feature set), whereas rule_weight is applied to a
    # small integer count of triggered rules -- these defaults are
    # illustrative starting points, as the write-up notes, and are meant
    # to be tuned from the Configure Rules screen against real traffic.
    rule_weight = db.Column(db.Float, nullable=False, default=25.0)
    ml_weight = db.Column(db.Float, nullable=False, default=150.0)
    high_risk_threshold = db.Column(db.Float, nullable=False, default=40.0)

    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
