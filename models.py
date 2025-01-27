# models.py
from flask_sqlalchemy import SQLAlchemy
import pyotp
from flask_login import UserMixin
import bcrypt
from datetime import datetime, timedelta
import re
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)  # Nowy atrybut `id`
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, nullable=True)
    full_name = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    blocked = db.Column(db.Boolean, default=False)
    password_expiry_date = db.Column(db.DateTime, nullable=True)
    password_history = db.Column(db.PickleType, nullable=False, default=lambda: [])
    is_admin_created = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

    def __init__(
        self, username, password, full_name, is_admin=False, is_admin_created=False
    ):
        self.username = username
        self.full_name = full_name
        self.is_admin = is_admin
        self.is_admin_created = is_admin_created
        self.blocked = False
        self.is_admin_created = False
        self.password_expiry_date = None
        self.password_history = []
        self.set_password(password)

        if is_admin_created:
            self.must_change_password = True

    def set_password(self, password):

        if not self.validate_password(password):
            raise ValueError("Password does not meet the complexity requirements.")

        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        self.password_history.append(self.password_hash)

    def validate_password(self, password):
        # Password complexity rules
        if not re.search(r"[a-z]", password):  # Wymaganie małych liter
            return False
        if not re.search(
            r"[!@#$%^&*(),.?\":{}|<>]", password
        ):  # Wymaganie znaków specjalnych
            return False
        return True

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    def set_new_password(self, new_password):
        new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        if new_hash not in self.password_history:
            self.password_hash = new_hash
            self.password_history.append(new_hash)
            self.must_change_password = False
            return True
        return False

    def reset_password_expiry(self, days):
        self.password_expiry_date = datetime.utcnow() + timedelta(days=days)

    def is_password_expired(self):
        if self.password_expiry_date and datetime.utcnow() > self.password_expiry_date:
            return True
        return False
