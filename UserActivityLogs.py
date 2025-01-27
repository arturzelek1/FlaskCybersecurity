# UserActivity logs
from extensions import db
from flask_login import UserMixin
from datetime import datetime
import pytz
import re


class UserActivityLog(db.Model):
    __tablename__ = "user_activity_logs"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(
        db.DateTime, nullable=False
    )  # Pole timestamp musi być kolumną typu DateTime
    status = db.Column(db.String(50), nullable=False)


def log_activity(username, action, status):
    # Ustawienie strefy czasowej UTC i konwersja na Warszawę
    utc = pytz.utc  # Definiujemy strefę czasową UTC
    warsaw_tz = pytz.timezone("Europe/Warsaw")  # Definiujemy strefę Warszawa
    timestamp = datetime.now(utc).astimezone(
        warsaw_tz
    )  # Pobieramy aktualny czas i konwertujemy na Warszawę

    # Tworzenie loga aktywności
    log_entry = UserActivityLog(
        username=username, action=action, status=status, timestamp=timestamp
    )
    db.session.add(log_entry)
    db.session.commit()
