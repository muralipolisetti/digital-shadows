"""
integrity.py
------------
File Integrity Monitoring core (SHA-256).

WHAT THIS DOES
    It calculates the SHA-256 hash of a protected file and compares it with a
    trusted baseline hash that was recorded earlier. If the two hashes differ,
    the file's contents changed, so tampering is reported.

WHAT THIS DOES *NOT* DO  (important - explain this to the judges)
    SHA-256 does not lock, protect or freeze a file. Anyone with write access
    to protected_data.txt can still edit or delete it. Hashing cannot prevent
    that. What it gives us is *detection*: a modification of even one byte
    produces a completely different hash, so the change cannot go unnoticed.

    The feature is therefore FILE INTEGRITY MONITORING + TAMPER DETECTION,
    not tamper prevention.

DESIGN NOTES
    - Files are read in binary mode ("rb") so the hash is identical on any
      operating system and is not affected by text encoding.
    - Files are read in fixed-size chunks so a very large file never has to be
      loaded into memory all at once.
    - This module never writes to the baseline file. The baseline is the
      trusted reference; if the program could rewrite it after detecting
      tampering, an attacker's change would silently become the new "truth".
      Updating the baseline is a deliberate, manual action (see
      create_baseline.py).
"""

import hashlib
import os
import re

# 64 KB per read. Big enough to be fast, small enough to stay memory-friendly.
CHUNK_SIZE = 65536

# A valid SHA-256 hex digest is exactly 64 hexadecimal characters.
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(Exception):
    """
    Raised for any expected, explainable problem (missing file, unreadable
    file, corrupt baseline). Flask catches this and turns it into a clean
    message, so the user never sees a Python stack trace.
    """


def calculate_hash(file_path, chunk_size=CHUNK_SIZE):
    """
    Return the SHA-256 hex digest of the file at `file_path`.

    Raises IntegrityError if the file is missing or cannot be read.
    """
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as handle:
            # iter(callable, sentinel) keeps calling handle.read() until it
            # returns b"" (end of file), feeding one chunk at a time.
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                sha256.update(chunk)
    except FileNotFoundError:
        raise IntegrityError(
            "Protected file not found: %s" % os.path.basename(file_path)
        )
    except IsADirectoryError:
        raise IntegrityError(
            "Expected a file but found a folder: %s" % os.path.basename(file_path)
        )
    except PermissionError:
        raise IntegrityError(
            "Permission denied while reading %s" % os.path.basename(file_path)
        )
    except OSError:
        raise IntegrityError(
            "Could not read %s" % os.path.basename(file_path)
        )

    return sha256.hexdigest()


def normalize_hash(value):
    """
    Clean up a hash string: strip whitespace/newlines and lowercase it, so
    that 'ABC...' and 'abc...\n' compare as equal.
    """
    return (value or "").strip().lower()


def is_valid_hash(value):
    """True if `value` looks like a real SHA-256 hex digest."""
    return bool(_HASH_PATTERN.match(normalize_hash(value)))


def read_baseline_hash(baseline_path):
    """
    Read the trusted baseline hash from disk and validate it.

    Raises IntegrityError if the file is missing, empty, or does not contain
    a valid 64-character SHA-256 hex digest.
    """
    try:
        with open(baseline_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except FileNotFoundError:
        raise IntegrityError(
            "Baseline file not found: %s. Create it by running "
            "create_baseline.py." % os.path.basename(baseline_path)
        )
    except PermissionError:
        raise IntegrityError(
            "Permission denied while reading %s" % os.path.basename(baseline_path)
        )
    except OSError:
        raise IntegrityError(
            "Could not read %s" % os.path.basename(baseline_path)
        )

    # Some baseline files are written as "protected_data.txt  <hash>" or with
    # a trailing newline. Take the last whitespace-separated token and check it.
    parts = raw.split()
    candidate = normalize_hash(parts[-1]) if parts else ""

    if not candidate:
        raise IntegrityError(
            "Baseline file %s is empty." % os.path.basename(baseline_path)
        )
    if not is_valid_hash(candidate):
        raise IntegrityError(
            "Baseline file %s does not contain a valid SHA-256 hash "
            "(expected 64 hex characters)." % os.path.basename(baseline_path)
        )

    return candidate


def verify_integrity(file_path, expected_hash):
    """
    Compare the current hash of `file_path` with `expected_hash`.

    Returns a plain dictionary so Flask can send it straight to the template
    or serialise it as JSON:

        {
            "status":        "SAFE" | "TAMPERING_DETECTED",
            "tampered":      False | True,
            "file":          "protected_data.txt",
            "expected_hash": "<64 hex chars>",
            "current_hash":  "<64 hex chars>"
        }

    Raises IntegrityError if the file cannot be hashed or the expected hash
    is not a valid digest.
    """
    expected = normalize_hash(expected_hash)
    if not is_valid_hash(expected):
        raise IntegrityError("The expected hash is not a valid SHA-256 digest.")

    current = calculate_hash(file_path)
    tampered = (current != expected)

    return {
        "status": "TAMPERING_DETECTED" if tampered else "SAFE",
        "tampered": tampered,
        "file": os.path.basename(file_path),
        "expected_hash": expected,
        "current_hash": current,
    }


def check_file(file_path, baseline_path):
    """
    Convenience wrapper used by the Flask routes: read the baseline from disk
    and verify the protected file against it in one call.

    Note the order of operations - the hash is recalculated on every call, so
    the result always reflects the file as it is on disk right now. Nothing is
    cached and nothing is hardcoded.
    """
    expected = read_baseline_hash(baseline_path)
    return verify_integrity(file_path, expected)


# Allows a quick check from the terminal:  python integrity.py
if __name__ == "__main__":
    import config

    try:
        result = check_file(config.PROTECTED_FILE, config.BASELINE_FILE)
        print("File          :", result["file"])
        print("Expected hash :", result["expected_hash"])
        print("Current hash  :", result["current_hash"])
        print("Result        :", result["status"])
    except IntegrityError as error:
        print("ERROR:", error)
