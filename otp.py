import pyotp


def generate_otp_secret():
    return pyotp.random_base32()


def get_current_otp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)
