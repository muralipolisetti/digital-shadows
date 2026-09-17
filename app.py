"""
app.py
------
SecureApp - Flask backend for File Integrity Monitoring.

Routes
    GET  /                      Security dashboard (HTML)
    GET  /login                 Login page
    POST /login                 Prototype login handling
    GET  /logout                Clear the session
    GET  /integrity             Run a check and show the result page (HTML)
    GET  /api/integrity         Run a check, return JSON
    GET  /api/security-status   Current security state + timestamp, JSON

Key rule: the hash is recalculated from disk on EVERY request. No result is
cached and no hash is hardcoded, so editing protected_data.txt in Notepad
changes the answer immediately, with no code changes and no restart.
"""

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import audit_log
import auth
import config
import integrity

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

audit_log.setup_logging()
audit_log.log_event("SecureApp started, monitoring %s" % config.PROTECTED_FILE_NAME)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def timestamp():
    """Human-readable local timestamp, matching the log format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_check(source):
    """
    Run one integrity check and write it to the audit log.

    Returns (result_dict, error_message). Exactly one of the two is None.
    Every expected failure arrives here as an IntegrityError, so no stack
    trace ever reaches the browser.
    """
    try:
        result = integrity.check_file(config.PROTECTED_FILE, config.BASELINE_FILE)
    except integrity.IntegrityError as error:
        message = str(error)
        audit_log.log_error(message, source=source)
        return None, message

    audit_log.log_integrity_check(result, source=source)
    return result, None


def login_required(view):
    """Redirect to the login page if there is no session."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def api_login_required(view):
    """
    Same idea for the JSON APIs, but returns 401 JSON instead of a redirect.
    Controlled by config.REQUIRE_AUTH_FOR_API, which is False by default so
    the frontend teammate can call the endpoints while developing.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if config.REQUIRE_AUTH_FOR_API and not session.get("user"):
            return jsonify({"error": "Authentication required"}), 401
        return view(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# HTML routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    """Main security dashboard. Runs a live check and renders index.html."""
    result, error = run_check(source="dashboard")
    return render_template(
        "index.html",
        result=result,
        error=error,
        monitored_file=config.PROTECTED_FILE_NAME,
        checked_at=timestamp(),
        user=session.get("user"),
        recent_log=audit_log.read_recent(10),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Prototype login. Passwords are compared against a PBKDF2 hash in auth.py
    and are never stored, logged or printed.
    """
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid, message = auth.validate_input(username, password)
        if not valid:
            error = message
            audit_log.log_login(username, success=False)
        elif auth.check_credentials(username, password):
            session["user"] = username.strip()
            audit_log.log_login(username, success=True)
            return redirect(url_for("dashboard"))
        else:
            # Same message for a wrong username and a wrong password, so the
            # form does not reveal which usernames exist.
            error = "Incorrect username or password."
            audit_log.log_login(username, success=False)

        # The password variable goes out of scope here. It is never reused.

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    user = session.pop("user", None)
    if user:
        audit_log.log_event("Logout: user=%s" % user)
    return redirect(url_for("login"))


@app.route("/integrity")
@login_required
def integrity_page():
    """Run a check on demand and show the detailed result page."""
    result, error = run_check(source="integrity-page")
    return render_template(
        "integrity.html",
        result=result,
        error=error,
        monitored_file=config.PROTECTED_FILE_NAME,
        checked_at=timestamp(),
        user=session.get("user"),
    )


# ---------------------------------------------------------------------------
# JSON API routes (for the frontend teammate)
# ---------------------------------------------------------------------------

@app.route("/api/integrity")
@api_login_required
def api_integrity():
    """
    Live integrity check as JSON.

        { "status": "SAFE", "tampered": false,
          "file": "protected_data.txt",
          "expected_hash": "...", "current_hash": "..." }
    """
    result, error = run_check(source="api/integrity")
    if error:
        return jsonify({"status": "ERROR", "error": error}), 500
    return jsonify(result)


@app.route("/api/security-status")
@api_login_required
def api_security_status():
    """
    Overall security state as JSON, with a timestamp.

        { "integrity": "SAFE", "tampering_detected": false,
          "monitored_file": "protected_data.txt",
          "expected_hash": "...", "current_hash": "...",
          "timestamp": "..." }
    """
    result, error = run_check(source="api/security-status")

    if error:
        return jsonify({
            "integrity": "ERROR",
            "tampering_detected": None,
            "monitored_file": config.PROTECTED_FILE_NAME,
            "expected_hash": None,
            "current_hash": None,
            "error": error,
            "timestamp": timestamp(),
        }), 500

    return jsonify({
        "integrity": result["status"],
        "tampering_detected": result["tampered"],
        "monitored_file": result["file"],
        "expected_hash": result["expected_hash"],
        "current_hash": result["current_hash"],
        "timestamp": timestamp(),
    })


# ---------------------------------------------------------------------------
# Error handlers - the browser gets a clean message, never a stack trace
# ---------------------------------------------------------------------------

def wants_json():
    return request.path.startswith("/api/")


@app.errorhandler(404)
def not_found(_error):
    if wants_json():
        return jsonify({"error": "Endpoint not found"}), 404
    return "Page not found. Try <a href='/'>the dashboard</a>.", 404


@app.errorhandler(500)
@app.errorhandler(Exception)
def internal_error(error):
    """
    Catch-all. Anything unexpected is logged locally and replaced with a
    short message, so Python internals are never shown to the user.
    """
    audit_log.log_error("Unhandled: %s: %s" % (type(error).__name__, error),
                        source=request.path)
    if wants_json():
        return jsonify({"error": "Internal server error"}), 500
    return "Something went wrong. Check security.log for details.", 500


if __name__ == "__main__":
    print("SecureApp - File Integrity Monitoring")
    print("Project folder :", config.BASE_DIR)
    print("Monitoring     :", config.PROTECTED_FILE)
    print("Baseline       :", config.BASELINE_FILE)
    print("Audit log      :", config.LOG_FILE)
    print("Open           : http://127.0.0.1:5000/login")
    # debug=False keeps Werkzeug's interactive traceback page turned off.
    app.run(host="127.0.0.1", port=5000, debug=False)
