"""
audit_log.py
------------
Security audit trail for SecureApp.

Every integrity check, login attempt and error is appended to security.log
with a timestamp. The log is append-only from the application's point of
view: entries are added, never rewritten. That is what makes it an audit
trail rather than a status file.

RULE: passwords are NEVER written here, and no password is ever printed to
the terminal. Only the username and the outcome (success/failure) are logged.

Log line format:
    2026-09-17 17:30:00 | INTEGRITY | protected_data.txt | TAMPERING_DETECTED | expected=... | current=...
"""

import logging

import config

# A named logger keeps our records separate from Flask's own request log.
_logger = logging.getLogger("secureapp.audit")


def setup_logging():
    """
    Attach a file handler to security.log. Safe to call more than once -
    the guard stops duplicate handlers (which would double every line).
    """
    if _logger.handlers:
        return _logger

    _logger.setLevel(logging.INFO)
    _logger.propagate = False  # don't spill audit records into the console log

    handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    _logger.addHandler(handler)
    return _logger


def log_integrity_check(result, source="web"):
    """
    Record the outcome of one integrity check.

    `result` is the dictionary returned by integrity.verify_integrity().
    `source` says where the check came from (dashboard, api, cli...).
    """
    _logger.info(
        "INTEGRITY | %s | %s | expected=%s | current=%s | source=%s",
        result["file"],
        result["status"],
        result["expected_hash"],
        result["current_hash"],
        source,
    )


def log_error(message, source="web"):
    """Record a handled error (missing file, bad baseline, and so on)."""
    _logger.info("ERROR | %s | source=%s", message, source)


def log_login(username, success):
    """
    Record a login attempt. The password is deliberately not passed into
    this function at all, so it cannot be logged by accident.
    """
    _logger.info(
        "LOGIN | user=%s | %s",
        username or "(empty)",
        "SUCCESS" if success else "FAILURE",
    )


def log_event(message):
    """Record any other noteworthy event (startup, logout, ...)."""
    _logger.info("EVENT | %s", message)


def read_recent(limit=25):
    """
    Return the most recent log lines (newest last), for showing on the
    dashboard. Returns an empty list if the log does not exist yet.
    """
    try:
        with open(config.LOG_FILE, "r", encoding="utf-8") as handle:
            lines = [line.rstrip("\n") for line in handle if line.strip()]
    except (FileNotFoundError, OSError):
        return []
    return lines[-limit:]
