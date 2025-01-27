import random
import bcrypt
from extensions import db


def generate_one_time_password(id):
    a = len(id)
    x = random.uniform(1, 1000)

    y = a / x

    y_hashed = bcrypt.hashpw(str(y).encode("utf-8"), bcrypt.gensalt())

    return x, y_hashed
