# create_admin.py
from app import app, db
from models import User


def create_admin():
    with app.app_context():
        if not User.query.filter_by(username="ADMIN").first():
            admin_user = User(
                username="ADMIN",
                password="admin123!",
                full_name="Administrator",
                is_admin=True,
            )
            db.session.add(admin_user)
            db.session.commit()
            print("ADMIN user created.")
        else:
            print("ADMIN user already exists.")


if __name__ == "__main__":
    create_admin()
