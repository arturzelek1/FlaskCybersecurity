# config.py
import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "your_secret_key_here"
    SQLALCHEMY_DATABASE_URI = "sqlite:///users.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
