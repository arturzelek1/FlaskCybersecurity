import bcrypt
import getpass
import datetime


# Klasa reprezentująca użytkownika
class User:
    def __init__(self, username, password, full_name, is_admin=False):
        self.username = username
        self.password_hash = self.hash_password(password)
        self.full_name = full_name
        self.is_admin = is_admin
        self.blocked = False
        self.password_expiry_date = None
        self.password_history = [self.password_hash]

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash)

    def set_password(self, new_password):
        if self.hash_password(new_password) not in self.password_history:
            self.password_hash = self.hash_password(new_password)
            self.password_history.append(self.password_hash)
            return True
        return False

    def reset_password_expiry(self, days):
        self.password_expiry_date = datetime.datetime.now() + datetime.timedelta(
            days=days
        )


# Klasa zarządzająca systemem bezpieczeństwa
class SecuritySystem:
    def __init__(self):
        self.users = {
            "ADMIN": User("ADMIN", "admin123", "Administrator", is_admin=True)
        }
        self.logged_in_user = None

    def login(self):
        username = input("Podaj identyfikator: ")
        password = getpass.getpass("Podaj hasło: ")

        if username in self.users and self.users[username].check_password(password):
            if self.users[username].blocked:
                print("Konto jest zablokowane.")
                return False

            self.logged_in_user = self.users[username]

            if self.is_password_expired(self.logged_in_user):
                print("Twoje hasło wygasło. Musisz ustawić nowe.")
                self.change_password()

            if self.logged_in_user.is_admin:
                print("Zalogowano jako administrator.")
                self.admin_menu()
            else:
                print(f"Zalogowano jako {self.logged_in_user.username}.")
                self.user_menu()

            return True
        else:
            print("Login lub hasło niepoprawny.")
            return False

    def is_password_expired(self, user):
        if (
            user.password_expiry_date
            and datetime.datetime.now() > user.password_expiry_date
        ):
            return True
        return False

    def admin_menu(self):
        while True:
            print("\n--- Menu Administratora ---")
            print("1. Zmień hasło")
            print("2. Dodaj nowego użytkownika")
            print("3. Przeglądaj listę użytkowników")
            print("4. Zablokuj konto użytkownika")
            print("5. Usuń konto użytkownika")
            print("6. Ustaw ważność hasła użytkownika")
            print("7. Wyloguj")

            choice = input("Wybierz opcję: ")

            if choice == "1":
                self.change_password()
            elif choice == "2":
                self.add_user()
            elif choice == "3":
                self.list_users()
            elif choice == "4":
                self.block_user()
            elif choice == "5":
                self.delete_user()
            elif choice == "6":
                self.set_password_expiry()
            elif choice == "7":
                self.logout()
                break
            else:
                print("Nieprawidłowy wybór.")

    def user_menu(self):
        while True:
            print("\n--- Menu Użytkownika ---")
            print("1. Zmień hasło")
            print("2. Wyloguj")

            choice = input("Wybierz opcję: ")

            if choice == "1":
                self.change_password()
            elif choice == "2":
                self.logout()
                break
            else:
                print("Nieprawidłowy wybór.")

    def change_password(self):
        old_password = getpass.getpass("Podaj stare hasło: ")
        if not self.logged_in_user.check_password(old_password):
            print("Stare hasło jest nieprawidłowe.")
            return

        new_password = getpass.getpass("Podaj nowe hasło: ")
        new_password_repeat = getpass.getpass("Powtórz nowe hasło: ")

        if new_password != new_password_repeat:
            print("Hasła nie pasują do siebie.")
            return

        if self.logged_in_user.set_password(new_password):
            print("Hasło zostało zmienione.")
        else:
            print("Nowe hasło musi się różnić od poprzednich haseł.")

    def add_user(self):
        username = input("Podaj nazwę użytkownika: ")
        if username in self.users:
            print("Użytkownik o tej nazwie już istnieje.")
            return

        password = getpass.getpass("Podaj hasło dla nowego użytkownika: ")
        full_name = input("Podaj pełne imię i nazwisko: ")

        self.users[username] = User(username, password, full_name)
        print(f"Użytkownik {username} został dodany.")

    def list_users(self):
        print("\nLista użytkowników:")
        for username, user in self.users.items():
            print(f"{username} - {'Administrator' if user.is_admin else 'Użytkownik'}")

    def block_user(self):
        username = input("Podaj nazwę użytkownika do zablokowania: ")
        if username in self.users:
            self.users[username].blocked = True
            print(f"Użytkownik {username} został zablokowany.")
        else:
            print("Użytkownik nie istnieje.")

    def delete_user(self):
        username = input("Podaj nazwę użytkownika do usunięcia: ")
        if username in self.users:
            del self.users[username]
            print(f"Użytkownik {username} został usunięty.")
        else:
            print("Użytkownik nie istnieje.")

    def set_password_expiry(self):
        username = input("Podaj nazwę użytkownika: ")
        if username in self.users:
            days = int(input("Podaj liczbę dni do wygaśnięcia hasła: "))
            self.users[username].reset_password_expiry(days)
            print(f"Hasło użytkownika {username} wygaśnie za {days} dni.")
        else:
            print("Użytkownik nie istnieje.")

    def logout(self):
        self.logged_in_user = None
        print("Wylogowano.")


# Główna pętla programu
def main():
    system = SecuritySystem()
    while True:
        print("\n--- System Logowania ---")
        if system.login():
            break


if __name__ == "__main__":
    main()
