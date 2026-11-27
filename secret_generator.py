import string
import secrets

def generate_secret(length=32):
    characters = string.ascii_letters + string.digits + string.punctuation.replace(" ", "")
    return ''.join(secrets.choice(characters) for _ in range(length))

for name in ("SECRET_KEY", "USER_PEPPER", "GROUP_PEPPER"):
    print(f"{name}={generate_secret()}")
