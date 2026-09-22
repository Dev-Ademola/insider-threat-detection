"""
extensions.py
-------------
Shared Flask extension instances (SQLAlchemy, LoginManager).

Kept in their own module (rather than instantiated in app.py) so that
models.py, and the detection modules that need a DB session, can import
`db` without causing a circular import with app.py.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access the dashboard."
login_manager.login_message_category = "info"
