# forms.py
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    SubmitField,
    IntegerField,
    HiddenField,
)
from wtforms.validators import DataRequired, EqualTo, Length


class LoginForm(FlaskForm):
    username = StringField("Identifikator", validators=[DataRequired()])
    password = PasswordField("Hasło", validators=[DataRequired()])
    submit = SubmitField("Zaloguj")


class RegisterForm(FlaskForm):
    username = StringField("Identifikator", validators=[DataRequired()])
    full_name = StringField("Full name", validators=[DataRequired()])
    password = PasswordField("Hasło", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Powtórz hasło", validators=[DataRequired(), EqualTo("password")]
    )


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Stare Hasło", validators=[DataRequired()])
    new_password = PasswordField(
        "Nowe Hasło", validators=[DataRequired(), Length(min=6)]
    )
    confirm_password = PasswordField(
        "Powtórz Nowe Hasło", validators=[DataRequired(), EqualTo("new_password")]
    )
    submit = SubmitField("Zmień Hasło")


class AddUserForm(FlaskForm):
    username = StringField("Nazwa Użytkownika", validators=[DataRequired()])
    password = PasswordField("Hasło", validators=[DataRequired(), Length(min=6)])
    full_name = StringField("Pełne Imię i Nazwisko", validators=[DataRequired()])
    is_admin = BooleanField("Administrator")
    submit = SubmitField("Dodaj Użytkownika")
    is_admin_created = HiddenField(default="True")


class SetPasswordExpiryForm(FlaskForm):
    username = StringField("Nazwa Użytkownika", validators=[DataRequired()])
    days = IntegerField("Liczba Dni do Wygaśnięcia Hasła", validators=[DataRequired()])
    submit = SubmitField("Ustaw Wygaśnięcie Hasła")
