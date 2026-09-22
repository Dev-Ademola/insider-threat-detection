"""
app.py
------
The Flask application providing the web dashboard and routes described in
Section 3.7.2 (use cases: Login, Upload/Import Activity Logs, View
Dashboard, View Alerts, Investigate/Update Alert Status, Configure
Detection Rules and Thresholds, Generate Reports) and Section 3.9
(Input/Output Design).

Run with:
    python init_db.py     # one-time: creates tables, default admin, demo data
    python app.py          # starts the dev server on http://127.0.0.1:5000
"""

import csv
import io
import json
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, redirect, url_for, request, flash, session,
    Response, send_file, abort,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db, login_manager
from models import Admin, MonitoredUser, ActivityLog, Alert, UserBaseline, RuleConfig
from data_ingestion import import_activity_csv, load_synthetic_data_into_db, IngestionError
from risk_scoring import run_detection_cycle
from rule_engine import get_active_config


def create_app(database_uri: str = "sqlite:///insider_threat.db") -> Flask:
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "dev-secret-key-change-in-production"

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(admin_id):
        return db.session.get(Admin, int(admin_id))

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:

    # ------------------------------------------------------------------ #
    # Login (Figure 3.7 mock-up: Username, Password, Login button)
    # ------------------------------------------------------------------ #
    @app.route("/", methods=["GET"])
    def index():
        return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            admin = Admin.query.filter_by(admin_username=username).first()

            if admin and check_password_hash(admin.password_hash, password):
                admin.last_login = datetime.utcnow()
                db.session.commit()
                login_user(admin)
                next_url = request.args.get("next")
                return redirect(next_url or url_for("dashboard"))

            flash("Invalid username or password.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ #
    # Dashboard (Figure 3.8 mock-up: summary panels, alerts-over-time
    # chart, recent high-risk alerts table)
    # ------------------------------------------------------------------ #
    @app.route("/dashboard")
    @login_required
    def dashboard():
        total_users = MonitoredUser.query.count()
        total_activities = ActivityLog.query.count()
        open_alerts = Alert.query.filter_by(status="open").count()
        avg_risk_score = db.session.query(db.func.avg(Alert.risk_score)).scalar() or 0.0

        # Alerts-over-time: count of alerts generated per day, last 14 days
        since = datetime.utcnow() - timedelta(days=14)
        recent_alerts = Alert.query.filter(Alert.date_generated >= since).all()
        counts_by_day = {}
        for a in recent_alerts:
            day = a.date_generated.date().isoformat()
            counts_by_day[day] = counts_by_day.get(day, 0) + 1
        chart_labels = sorted(counts_by_day.keys())
        chart_values = [counts_by_day[d] for d in chart_labels]

        recent_high_risk = (
            Alert.query.order_by(Alert.risk_score.desc(), Alert.date_generated.desc()).limit(10).all()
        )

        return render_template(
            "dashboard.html",
            total_users=total_users,
            total_activities=total_activities,
            open_alerts=open_alerts,
            avg_risk_score=round(avg_risk_score, 1),
            chart_labels=json.dumps(chart_labels),
            chart_values=json.dumps(chart_values),
            recent_high_risk=recent_high_risk,
        )

    # ------------------------------------------------------------------ #
    # Upload / Import Activity Logs
    # ------------------------------------------------------------------ #
    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "load_demo_data":
                    summary = load_synthetic_data_into_db()
                    flash(
                        f"Loaded synthetic demo data: {summary['users_created']} users, "
                        f"{summary['logs_created']} activity log entries.",
                        "success",
                    )
                else:
                    file = request.files.get("csv_file")
                    if not file or file.filename == "":
                        flash("Please choose a CSV file to upload.", "warning")
                        return redirect(url_for("upload"))
                    summary = import_activity_csv(file.stream)
                    flash(
                        f"Imported {summary['logs_created']} activity records "
                        f"({summary['users_created']} new users).",
                        "success",
                    )
            except IngestionError as exc:
                flash(f"Import failed: {exc}", "danger")
            return redirect(url_for("upload"))

        return render_template("upload.html")

    @app.route("/run-detection", methods=["POST"])
    @login_required
    def run_detection():
        summary = run_detection_cycle()
        flash(
            f"Detection cycle complete: {summary['activities_scored']} activities scored, "
            f"{summary['alerts_created']} new alert(s) generated.",
            "info",
        )
        return redirect(request.referrer or url_for("dashboard"))

    # ------------------------------------------------------------------ #
    # Alerts list + investigate/update status
    # ------------------------------------------------------------------ #
    @app.route("/alerts")
    @login_required
    def alerts():
        status_filter = request.args.get("status", "")
        min_score = request.args.get("min_score", type=float)

        query = Alert.query
        if status_filter:
            query = query.filter_by(status=status_filter)
        if min_score is not None:
            query = query.filter(Alert.risk_score >= min_score)

        alert_list = query.order_by(Alert.date_generated.desc()).all()
        return render_template(
            "alerts.html", alerts=alert_list, status_filter=status_filter, min_score=min_score
        )

    @app.route("/alerts/<int:alert_id>", methods=["GET", "POST"])
    @login_required
    def alert_detail(alert_id):
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            abort(404)

        if request.method == "POST":
            new_status = request.form.get("status")
            if new_status in ("open", "reviewed", "false_positive", "escalated"):
                alert.status = new_status
                db.session.commit()
                flash(f"Alert #{alert.alert_id} marked as '{new_status}'.", "success")
            return redirect(url_for("alert_detail", alert_id=alert_id))

        activity = db.session.get(ActivityLog, alert.log_id)
        user = db.session.get(MonitoredUser, alert.user_id)
        return render_template("alert_detail.html", alert=alert, activity=activity, user=user)

    # ------------------------------------------------------------------ #
    # Per-user risk profile page
    # ------------------------------------------------------------------ #
    @app.route("/users/<int:user_id>")
    @login_required
    def user_profile(user_id):
        user = db.session.get(MonitoredUser, user_id)
        if user is None:
            abort(404)

        baseline = UserBaseline.query.filter_by(user_id=user_id).first()
        activities = (
            ActivityLog.query.filter_by(user_id=user_id).order_by(ActivityLog.timestamp).all()
        )
        user_alerts = (
            Alert.query.filter_by(user_id=user_id).order_by(Alert.date_generated.desc()).all()
        )

        daily_volume = {}
        for act in activities:
            day = act.timestamp.date().isoformat()
            daily_volume[day] = daily_volume.get(day, 0.0) + (act.data_volume_mb or 0.0)
        trend_labels = sorted(daily_volume.keys())
        trend_values = [round(daily_volume[d], 1) for d in trend_labels]

        return render_template(
            "user_profile.html",
            user=user,
            baseline=baseline,
            activities=activities,
            user_alerts=user_alerts,
            trend_labels=json.dumps(trend_labels),
            trend_values=json.dumps(trend_values),
        )

    # ------------------------------------------------------------------ #
    # Configure Detection Rules and Thresholds
    # ------------------------------------------------------------------ #
    @app.route("/rules", methods=["GET", "POST"])
    @login_required
    def rules():
        config = get_active_config()

        if request.method == "POST":
            try:
                config.login_start_hour = int(request.form["login_start_hour"])
                config.login_end_hour = int(request.form["login_end_hour"])
                config.max_download_mb = float(request.form["max_download_mb"])
                config.rule_weight = float(request.form["rule_weight"])
                config.ml_weight = float(request.form["ml_weight"])
                config.high_risk_threshold = float(request.form["high_risk_threshold"])

                restricted_raw = request.form.get("restricted_resources_json", "{}")
                json.loads(restricted_raw)  # validate it parses
                config.restricted_resources_json = restricted_raw

                config.updated_at = datetime.utcnow()
                db.session.commit()
                flash("Detection rules and thresholds updated.", "success")
            except (KeyError, ValueError) as exc:
                flash(f"Could not save rules: {exc}", "danger")
            return redirect(url_for("rules"))

        return render_template("rules.html", config=config)

    # ------------------------------------------------------------------ #
    # Generate Reports (Section 3.9.2: downloadable/printable CSV/PDF)
    # ------------------------------------------------------------------ #
    @app.route("/reports", methods=["GET", "POST"])
    @login_required
    def reports():
        if request.method == "POST":
            start = datetime.strptime(request.form["start_date"], "%Y-%m-%d")
            end = datetime.strptime(request.form["end_date"], "%Y-%m-%d") + timedelta(days=1)
            fmt = request.form.get("format", "csv")

            alerts_in_range = (
                Alert.query.filter(Alert.date_generated >= start, Alert.date_generated < end)
                .order_by(Alert.date_generated)
                .all()
            )

            if fmt == "pdf":
                return _generate_pdf_report(alerts_in_range, start, end)
            return _generate_csv_report(alerts_in_range, start, end)

        return render_template("reports.html")


def _generate_csv_report(alerts_in_range, start, end) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["alert_id", "user_id", "username", "alert_type", "risk_score", "description", "status", "date_generated"])
    for a in alerts_in_range:
        user = db.session.get(MonitoredUser, a.user_id)
        writer.writerow(
            [a.alert_id, a.user_id, user.username if user else "", a.alert_type,
             f"{a.risk_score:.1f}", a.description, a.status, a.date_generated.isoformat()]
        )
    buffer.seek(0)
    filename = f"insider_threat_report_{start.date()}_{(end - timedelta(days=1)).date()}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _generate_pdf_report(alerts_in_range, start, end) -> Response:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    elements = [
        Paragraph("Insider Threat Detection System - Alert Report", styles["Title"]),
        Paragraph(f"Period: {start.date()} to {(end - timedelta(days=1)).date()}", styles["Normal"]),
        Spacer(1, 12),
    ]

    data = [["ID", "User", "Type", "Risk", "Status", "Generated"]]
    for a in alerts_in_range:
        user = db.session.get(MonitoredUser, a.user_id)
        data.append(
            [a.alert_id, user.username if user else "", a.alert_type,
             f"{a.risk_score:.1f}", a.status, a.date_generated.strftime("%Y-%m-%d %H:%M")]
        )

    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    filename = f"insider_threat_report_{start.date()}_{(end - timedelta(days=1)).date()}.pdf"
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=filename)


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
