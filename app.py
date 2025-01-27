# app.py
# app.py
from flask import Flask, render_template, redirect, url_for, flash, request, session
from config import Config
from models import db, User
from forms import (
    RegisterForm,
    LoginForm,
    ChangePasswordForm,
    AddUserForm,
    SetPasswordExpiryForm,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from UserActivityLogs import UserActivityLog, log_activity
from datetime import datetime, timedelta
import pytz
import bcrypt
import random
import string
import os

app = Flask(__name__)
app.config.from_object(Config)

# Inicjalizacja bazy danych
db.init_app(app)

# Inicjalizacja menedżera logowania
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Inicjalizacja migracji (opcjonalnie)
from flask_migrate import Migrate

migrate = Migrate(app, db)

# Tworzenie bazy danych przed pierwszym uruchomieniem
with app.app_context():
    db.create_all()
    # Sprawdzenie czy istnieje ADMIN, jeśli nie, utworzenie
    if not User.query.filter_by(username="ADMIN").first():
        admin_user = User(
            username="ADMIN",
            password="admin123!",
            full_name="Administrator",
            is_admin=True,
        )
        db.session.add(admin_user)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Użycie `id` jako klucza


@app.route("/")
def home():
    return redirect(url_for("login"))


from flask_login import current_user


@app.before_request
def check_active_session():
    utc = pytz.utc  # Definiujemy strefę czasową UTC
    warsaw_tz = pytz.timezone("Europe/Warsaw")
    timestamp = datetime.now(utc).astimezone(
        warsaw_tz
    )  # Pobieramy aktualny czas i konwertujemy na Warszawę
    if current_user.is_authenticated:
        if current_user.last_login_attempt and (
            datetime.astimezone(timestamp) - current_user.last_login_attempt
        ) > timedelta(minutes=15):
            logout_user()  # Wylogowanie użytkownika po 15 minutach nieaktywności


@app.route("/verify_otp", methods=["GET", "POST"])
@login_required
def verify_otp():
    if request.method == "POST":
        otp_input = request.form.get(
            "otp"
        )  # Otrzymane hasło jednorazowe od użytkownika

        # Pobierz wartość zahashowanego y (OTP) z sesji
        y_hashed = session.get("otp_hash")
        if not y_hashed:
            flash("Brak wygenerowanego OTP. Spróbuj ponownie.", "danger")
            return redirect(url_for("request_otp"))

        # Pobierz wartość x, którą użytkownik otrzymał wcześniej
        x = session.get("otp_x")
        if not x:
            flash("Brak kluczowej wartości x. Spróbuj ponownie.", "danger")
            return redirect(url_for("request_otp"))

        # Oblicz wartość y' po stronie użytkownika na podstawie danych
        a = len(
            current_user.username
        )  # Możesz tu użyć dowolnej wartości identyfikacyjnej
        try:
            y_prime = a / x  # Oblicz wartość y'
        except ZeroDivisionError:
            flash("Nieprawidłowa wartość x. Spróbuj ponownie.", "danger")
            return redirect(url_for("request_otp"))

        # Porównaj zahashowaną wartość y z wynikiem obliczeń użytkownika (bcrypt.checkpw)
        if bcrypt.checkpw(str(y_prime).encode("utf-8"), y_hashed.encode("utf-8")):
            flash("Hasło jednorazowe poprawne! Logowanie udane.", "success")
            # Możesz dodać dodatkową logikę, np. przekierowanie do panelu użytkownika
            return redirect(url_for("user_dashboard"))
        else:
            flash("Nieprawidłowe OTP. Spróbuj ponownie.", "danger")
            return redirect(url_for("verify_otp"))

    return render_template("verify_otp.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Sprawdzenie, czy użytkownik już istnieje
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Użytkownik z takim identyfikatorem już istnieje.", "danger")
            log_activity(
                current_user.username.data,
                "Rejestracja",
                "Próba utworzenia użytkownika o tej samej nazwie",
            )
            return redirect(url_for("register"))

        # Tworzenie nowego użytkownika
        new_user = User(
            username=form.username.data,
            password=form.password.data,  # Hasło powinno być zaszyfrowane w modelu
            full_name=form.full_name.data,  # Upewnij się, że pole 'full_name' jest dodane w formularzu
        )
        log_activity(current_user.username, "Rejestracja", "Sukces")
        # Dodawanie użytkownika do bazy danych
        db.session.add(new_user)
        db.session.commit()

        flash("Rejestracja przebiegła pomyślnie. Możesz się zalogować.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            # Sprawdzenie, czy konto jest zablokowane
            if user.blocked:
                flash("Konto jest zablokowane. Spróbuj ponownie później.", "danger")
                log_activity(
                    "Nieznany użytkownik",
                    "Logowanie",
                    "Próba logowania nieudana, konto zablokowane",
                )
                return redirect(url_for("login"))

            # Sprawdzenie hasła
            if user.check_password(form.password.data):
                # Resetowanie nieudanych prób logowania
                user.failed_login_attempts = 0
                user.is_blocked = False
                db.session.commit()

                login_user(user)
                x = random.randint(1, 100)  # Możesz dostosować zakres
                session["otp_x"] = x  # Przechowaj wartość x w sesji

                # Generowanie hasła jednorazowego (y)
                a = len(current_user.username)
                y = a / x

                # Hashowanie y i przechowywanie w sesji
                y_hashed = bcrypt.hashpw(
                    str(y).encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")
                session["otp_hash"] = y_hashed

                if user.must_change_password:
                    return redirect(url_for("change_password"))

                if user.is_password_expired():
                    flash("Twoje hasło wygasło. Musisz ustawić nowe.", "warning")
                    return redirect(url_for("change_password"))

                # Logowanie aktywności użytkownika
                if user.is_admin:
                    log_activity(
                        user.username, "Logowanie na konto administratora", "Sukces"
                    )
                    return redirect(url_for("admin_dashboard"))
                else:
                    log_activity(
                        user.username, "Logowanie na konto użytkownika", "Sukces"
                    )
                    return redirect(url_for("verify_otp"))
            else:
                # Zwiększanie liczby nieudanych prób logowania
                user.failed_login_attempts += 1
                user.last_login_attempt = datetime.utcnow()

                # Sprawdzenie, czy liczba prób przekracza dozwoloną liczbę
                if user.failed_login_attempts >= 3:
                    user.is_blocked = True
                    flash(
                        "Konto zostało zablokowane z powodu zbyt wielu nieudanych prób logowania.",
                        "danger",
                    )
                    log_activity(user.username, "Logowanie", "Konto zablokowane")
                else:
                    flash("Login lub hasło niepoprawne.", "danger")
                    log_activity(user.username, "Logowanie", "Nieudane")

                db.session.commit()
        else:
            flash("Login lub hasło niepoprawne.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    log_activity(
        current_user.username,
        "Wylogowanie",
        "Sukces",
    )
    logout_user()

    flash("Wylogowano pomyślnie.", "success")
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Dostęp ograniczony do administratorów.", "danger")
        return redirect(url_for("user_dashboard"))
    users = User.query.all()
    return render_template("admin_dashboard.html", users=users)


@app.route("/admin/add_user", methods=["GET", "POST"])
@login_required
def add_user():
    if not current_user.is_admin:
        flash("Dostęp ograniczony do administratorów.", "danger")
        return redirect(url_for("user_dashboard"))
    form = AddUserForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            log_activity(
                current_user.username.data,
                "Próba dodania nowego użytkownika",
                "Nieudana",
            )
            flash("Użytkownik o tej nazwie już istnieje.", "danger")
            return redirect(url_for("add_user"))
        new_user = User(
            username=form.username.data,
            password=form.password.data,
            full_name=form.full_name.data,
            is_admin=form.is_admin.data,
            is_admin_created=form.is_admin_created.data,
        )
        db.session.add(new_user)
        db.session.commit()
        log_activity(
            current_user.username,
            "Dodanie nowego użytkownika",
            "Sukces",
        )
        flash(f"Użytkownik {new_user.username} został dodany.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("add_user.html", form=form)


@app.route("/admin/block_user/<username>")
@login_required
def block_user(username):
    if not current_user.is_admin:
        log_activity(
            current_user.username.data,
            "Próba blokowania użytkownika",
            "Nieautoryzowana",
        )
        flash("Dostęp ograniczony do administratorów.", "danger")
        return redirect(url_for("user_dashboard"))
    user = User.query.filter_by(username=username).first()
    if user:
        user.blocked = True
        db.session.commit()
        log_activity(
            current_user.username.data,
            "Próba blokowania użytkownika",
            "Użytkownik już jest zablokowany",
        )
        flash(f"Użytkownik {username} został zablokowany.", "success")
    else:
        log_activity(
            current_user.username.data,
            "Próba blokowania użytkownika",
            "Użytkownik nie istnieje",
        )
        flash("Użytkownik nie istnieje.", "danger")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_user/<username>")
@login_required
def delete_user(username):
    if not current_user.is_admin:
        log_activity(
            current_user.username.data,
            "Próba usunięcia użytkownika",
            "Nieautoryzowana",
        )
        flash("Dostęp ograniczony do administratorów.", "danger")
        return redirect(url_for("user_dashboard"))
    user = User.query.filter_by(username=username).first()
    if user:
        if user.username == "ADMIN":
            flash("Nie można usunąć konta administratora.", "danger")
            return redirect(url_for("admin_dashboard"))
        db.session.delete(user)
        db.session.commit()
        log_activity(current_user.username, "Próba usunięcia użytkownika", "Sukces")
        flash(f"Użytkownik {username} został usunięty.", "success")
    else:
        flash("Użytkownik nie istnieje.", "danger")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/set_password_expiry", methods=["GET", "POST"])
@login_required
def set_password_expiry():
    if not current_user.is_admin:
        flash("Dostęp ograniczony do administratorów.", "danger")
        return redirect(url_for("user_dashboard"))
    form = SetPasswordExpiryForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            user.reset_password_expiry(form.days.data)
            db.session.commit()
            log_activity(
                current_user.username,
                "Próba zmiany ważności hasła użytkownika",
                "Sukces",
            )
            flash(
                f"Hasło użytkownika {user.username} wygaśnie za {form.days.data} dni.",
                "success",
            )
            return redirect(url_for("admin_dashboard"))
        else:
            log_activity(
                current_user.username.data,
                "Próba zmiany ważności hasła użytkownika",
                "Nieudana",
            )
            flash("Użytkownik nie istnieje.", "danger")
    return render_template("set_password_expiry.html", form=form)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.old_password.data):
            flash("Stare hasło jest nieprawidłowe.", "danger")
            return redirect(url_for("change_password"))
        if form.new_password.data != form.confirm_password.data:
            flash("Hasła nie pasują do siebie.", "danger")
            return redirect(url_for("change_password"))
        if current_user.set_new_password(form.new_password.data):
            # Resetowanie daty wygaśnięcia hasła po zmianie
            current_user.reset_password_expiry(days=90)  # Przykładowo: 90 dni
            db.session.commit()
            log_activity(
                current_user.username,
                "Próba zmiany hasła użytkownika",
                "Sukces",
            )
            flash("Hasło zostało zmienione.", "success")
            if current_user.is_admin:
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("user_dashboard"))
        else:
            log_activity(
                current_user.username.data,
                "Próba zmiany ważności hasła użytkownika",
                "Nieudana",
            )
            flash("Nowe hasło musi się różnić od poprzednich haseł.", "danger")
    return render_template("change_password.html", form=form)


@app.route("/admin/activity_logs", methods=["GET"])
@login_required
def activity_logs():
    if not current_user.is_admin:
        flash("Brak uprawnień", "danger")
        return redirect(url_for("user_dashboard"))
    logs = UserActivityLog.query.all()
    return render_template("activity_logs.html", logs=logs)


@app.route("/user")
@login_required
def user_dashboard():
    if current_user.is_admin:
        flash("Administrator nie ma dostępu do tego panelu.", "danger")
        return redirect(url_for("admin_dashboard"))
    return render_template("user_dashboard.html")


# Funkcja do uruchomienia aplikacji
if __name__ == "__main__":
    app.run(debug=True)

migrate = Migrate(app, db)
