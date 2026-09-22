"""
init_db.py
----------
One-time setup script:
  1. Creates all tables (models.py)
  2. Creates a default Admin login (username: admin / password: admin123
     -- CHANGE THIS before any real use)
  3. Creates a default RuleConfig row with a sample restricted-resource map
  4. Optionally loads synthetic demo activity data and runs one detection
     cycle, so the dashboard has something to show immediately

Usage:
    python init_db.py                 # tables + admin + rule config only
    python init_db.py --with-demo-data  # also loads synthetic data + alerts
"""

import argparse
import json

from werkzeug.security import generate_password_hash

from app import create_app
from extensions import db
from models import Admin, RuleConfig


DEFAULT_RESTRICTED_RESOURCES = {
    "payroll_db": ["HR", "Finance", "Manager"],
    "source_code_repo": ["Software Engineer", "DevOps Engineer"],
    "hr_portal": ["HR Specialist", "Recruiter", "Manager"],
    "finance_reports": ["Analyst", "Accountant", "Manager"],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-demo-data", action="store_true", help="Load synthetic activity data and run a detection cycle")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password", default="admin123")
    parser.add_argument("--admin-email", default="admin@example.com")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        db.create_all()

        if not Admin.query.filter_by(admin_username=args.admin_username).first():
            admin = Admin(
                admin_username=args.admin_username,
                password_hash=generate_password_hash(args.admin_password),
                email=args.admin_email,
            )
            db.session.add(admin)
            print(f"Created default admin: {args.admin_username} / {args.admin_password} (change this password!)")
        else:
            print(f"Admin '{args.admin_username}' already exists, skipping.")

        if not RuleConfig.query.first():
            config = RuleConfig(restricted_resources_json=json.dumps(DEFAULT_RESTRICTED_RESOURCES))
            db.session.add(config)
            print("Created default RuleConfig.")
        else:
            print("RuleConfig already exists, skipping.")

        db.session.commit()

        if args.with_demo_data:
            from data_ingestion import load_synthetic_data_into_db
            from risk_scoring import run_detection_cycle

            summary = load_synthetic_data_into_db()
            print(f"Loaded demo data: {summary}")

            cycle_summary = run_detection_cycle()
            print(f"Ran detection cycle: {cycle_summary}")

    print("Database setup complete.")


if __name__ == "__main__":
    main()
