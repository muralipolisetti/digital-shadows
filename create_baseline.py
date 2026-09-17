"""
create_baseline.py
------------------
Record the trusted baseline hash for the protected file.

This is a SEPARATE, MANUAL step on purpose. The web application can never
write the baseline itself - if it could, an attacker's edit would quietly
become the new "trusted" version and tampering would never be reported.

Run it only when you know the file is in its correct, trusted state:

    python create_baseline.py

It shows the old and new hash and asks for confirmation before writing.
"""

import os

import config
import integrity


def main():
    if not os.path.exists(config.PROTECTED_FILE):
        print("Protected file not found:", config.PROTECTED_FILE)
        print("Create protected_data.txt first, then run this again.")
        return

    try:
        current = integrity.calculate_hash(config.PROTECTED_FILE)
    except integrity.IntegrityError as error:
        print("ERROR:", error)
        return

    print("File         :", config.PROTECTED_FILE)
    print("Current hash :", current)

    try:
        old = integrity.read_baseline_hash(config.BASELINE_FILE)
        print("Existing baseline:", old)
        if old == current:
            print("The baseline already matches this file. Nothing to do.")
            return
        print()
        print("WARNING: overwriting the baseline makes the file's CURRENT")
        print("contents the new trusted reference. Only continue if you are")
        print("certain the file has not been tampered with.")
    except integrity.IntegrityError:
        print("No usable baseline yet - a new one will be created.")

    answer = input("Write this hash to baseline_hash.txt? (yes/no): ").strip().lower()
    if answer != "yes":
        print("Cancelled. Baseline unchanged.")
        return

    with open(config.BASELINE_FILE, "w", encoding="utf-8") as handle:
        handle.write(current + "\n")

    print("Baseline written to", config.BASELINE_FILE)


if __name__ == "__main__":
    main()
