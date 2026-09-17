"""
create_user.py
--------------
Generate a salted PBKDF2 entry for auth.py so you can use your own demo
account instead of the built-in one.

    python create_user.py

The password is typed with getpass, so it is not echoed to the screen, not
written to the terminal history, and never saved anywhere. Only the salt and
the derived hash are printed - paste them into the _USERS dictionary in
auth.py.
"""

import getpass
import os

import auth


def main():
    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    password = getpass.getpass("Password (hidden): ")
    confirm = getpass.getpass("Confirm password: ")

    if not password:
        print("Password cannot be empty.")
        return
    if password != confirm:
        print("Passwords do not match.")
        return

    salt_hex = os.urandom(16).hex()
    digest = auth.hash_password(password, salt_hex)

    print()
    print("Paste this into the _USERS dictionary in auth.py:")
    print()
    print('    "%s": {' % username)
    print('        "salt": "%s",' % salt_hex)
    print('        "hash": "%s",' % digest)
    print("    },")


if __name__ == "__main__":
    main()
