import os
import json
import hashlib

USERS_FILE = "users.json"


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt),
        100000
    ).hex()


def register(username, password):

    users = load_users()

    if username in users:
        return False

    salt = os.urandom(16).hex()

    password_hash = hash_password(
        password,
        salt
    )

    users[username] = {
        "salt": salt,
        "password": password_hash
    }

    save_users(users)

    return True


def authenticate(username, password):

    users = load_users()

    if username not in users:
        return False

    salt = users[username]["salt"]

    expected_hash = users[username]["password"]

    entered_hash = hash_password(
        password,
        salt
    )

    return entered_hash == expected_hash