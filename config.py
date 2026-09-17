"""
config.py
---------
Central configuration for SecureApp.

Why this file exists:
Flask can be started from ANY folder (for example from C:\\ or from the
Desktop). If we wrote open("protected_data.txt") the program would look for
the file in whatever folder the terminal happens to be in, and the app would
break. So every path used by the project is built from the location of THIS
file instead of from the current working directory.
"""

import os

# Absolute path of the folder that contains this file (the project root).
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# --- Files used by the integrity monitor ---------------------------------
PROTECTED_FILE_NAME = "protected_data.txt"
BASELINE_FILE_NAME = "baseline_hash.txt"
LOG_FILE_NAME = "security.log"

PROTECTED_FILE = os.path.join(BASE_DIR, PROTECTED_FILE_NAME)
BASELINE_FILE = os.path.join(BASE_DIR, BASELINE_FILE_NAME)
LOG_FILE = os.path.join(BASE_DIR, LOG_FILE_NAME)

# --- Flask settings -------------------------------------------------------
# The secret key signs the session cookie. For a local hackathon prototype a
# random key per run is fine (it just means you are logged out on restart).
# For anything real, set the SECUREAPP_SECRET_KEY environment variable.
SECRET_KEY = os.environ.get("SECUREAPP_SECRET_KEY") or os.urandom(32)

# Set to True if you want /api/integrity and /api/security-status to require
# a logged-in session. It is False by default so the frontend teammate can
# call the APIs directly while developing.
REQUIRE_AUTH_FOR_API = False
