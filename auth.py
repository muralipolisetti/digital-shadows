"""
auth.py
-------
PROTOTYPE authentication for SecureApp.

This is deliberately small. The hackathon feature is file integrity
monitoring, not identity management. Everything a real system would need
(user database, registration, password reset, lockout after repeated
failures, multi-factor) is out of scope.

What it still does correctly, because these are cheap and matter:
  * No plaintext password is stored anywhere. The demo account is kept as a
    PBKDF2-HMAC-SHA256 hash with a random salt and 200,000 iterations.
  * Comparison uses hmac.compare_digest, which takes the same amount of time
    whatever the input, so an attacker cannot learn the password by timing.
  * Passwords are never logged and never printed.
  * Empty username or password is rejected before anything else happens.

Everything authentication-related lives behind check_credentials(), so this
whole file can be swapped for Flask-Login or a real user table without
touching app.py beyond the import.
"""

import hashlib
import hmac

# --- Demo account ---------------------------------------------------------
# Username: admin
# Password: SecureApp@2026
#
# The password itself does not appear below - only the salt and the derived
# key. To create your own account, run:  python create_user.py
_ITERATIONS = 200000

_USERS = {
    "admin": {
        "salt": "88182362fc0c2fcb5f9335fd6abeb335",
        "hash": "8bff9a6fdd06f1fec8048e584a0b6643b0810cd5f77d75909a29883cf8990486",
    }
}


def hash_password(password, salt_hex, iterations=_ITERATIONS):
    """Derive a hex key from a password and a hex salt using PBKDF2."""
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        iterations,
    )
    return derived.hex()


def validate_input(username, password):
    """
    Check the form fields before touching any credential logic.
    Returns (True, None) or (False, "message for the user").
    """
    if not username or not username.strip():
        return False, "Enter a username."
    if not password:
        return False, "Enter a password."
    return True, None


def check_credentials(username, password):
    """
    Return True if the username/password pair is valid.

    The password is only used inside this function and is never returned,
    stored, logged or printed.
    """
    username = (username or "").strip()
    record = _USERS.get(username)

    if record is None:
        # Still run a hash so that an unknown username takes roughly the same
        # time as a known one - otherwise the response time reveals which
        # usernames exist.
        hash_password(password or "", "00" * 16)
        return False

    candidate = hash_password(password or "", record["salt"])
    return hmac.compare_digest(candidate, record["hash"])
