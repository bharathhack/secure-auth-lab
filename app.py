"""Secure Authentication Lab - a small LOCAL authentication service (Flask).

Features
1. Password hashing (scrypt via Werkzeug) + server-side input validation
2. Secure cookie settings, logout, and session expiry
3. Rate limiting and generic authentication errors

Run locally only:  python app.py   ->  http://127.0.0.1:5000
"""
import re
import secrets
import sqlite3
import time
from datetime import timedelta

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- config
SESSION_LIFETIME_MIN = 15      # absolute session expiry
IDLE_TIMEOUT_SEC = 5 * 60      # idle expiry
MAX_ATTEMPTS = 5               # failed logins allowed per window
WINDOW_SEC = 60                # rate-limit window
LOCKOUT_SEC = 120              # lockout after too many failures

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
GENERIC_AUTH_ERROR = "Invalid username or password."

# A real hash of a random value, used so unknown usernames cost the same
# time as known ones (prevents user enumeration by timing).
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def create_app(db_path=":memory:"):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),          # random per start; use env var in prod
        SESSION_COOKIE_HTTPONLY=True,              # JS cannot read the cookie
        SESSION_COOKIE_SAMESITE="Lax",             # basic CSRF protection
        SESSION_COOKIE_SECURE=False,               # set True when served over HTTPS
        SESSION_COOKIE_NAME="sid",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_LIFETIME_MIN),
        MAX_CONTENT_LENGTH=4 * 1024,               # reject huge bodies
    )

    db = sqlite3.connect(db_path, check_same_thread=False)
    db.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)"
    )
    failures = {}  # key -> {"count", "start", "locked_until"}  (in-memory, lab only)

    # ------------------------------------------------------- validation
    def validate_credentials(username, password, strict_password=True):
        errors = []
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            errors.append("Username must be 3-20 characters: letters, digits, underscore.")
        if not isinstance(password, str):
            errors.append("Password is required.")
        elif strict_password:
            if not (10 <= len(password) <= 128):
                errors.append("Password must be 10-128 characters.")
            if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
                    and re.search(r"\d", password)):
                errors.append("Password needs lowercase, uppercase, and a digit.")
        return errors

    # ------------------------------------------------------ rate limit
    def limiter_key(username):
        return f"{request.remote_addr}|{(username or '').lower()}"

    def is_locked(key):
        rec = failures.get(key)
        return bool(rec and rec["locked_until"] > time.time())

    def record_failure(key):
        now = time.time()
        rec = failures.get(key)
        if not rec or now - rec["start"] > WINDOW_SEC:
            rec = {"count": 0, "start": now, "locked_until": 0}
            failures[key] = rec
        rec["count"] += 1
        if rec["count"] >= MAX_ATTEMPTS:
            rec["locked_until"] = now + LOCKOUT_SEC

    def retry_after(key):
        return max(1, int(failures[key]["locked_until"] - time.time()))

    # ----------------------------------------------------------- routes
    @app.post("/register")
    def register():
        data = request.get_json(silent=True) or {}
        username, password = data.get("username"), data.get("password")
        errors = validate_credentials(username, password)
        if errors:
            return jsonify(errors=errors), 400
        try:
            db.execute(
                "INSERT INTO users VALUES (?, ?)",  # parameterised: no SQL injection
                (username.lower(), generate_password_hash(password, method="scrypt")),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify(error="Registration failed."), 400  # generic: no enumeration
        return jsonify(message="Registered."), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        username, password = data.get("username"), data.get("password")
        key = limiter_key(username if isinstance(username, str) else "")

        if is_locked(key):
            resp = jsonify(error="Too many attempts. Try again later.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after(key))
            return resp

        # Shape check only (don't leak password policy at login)
        if validate_credentials(username, password, strict_password=False):
            record_failure(key)
            return jsonify(error=GENERIC_AUTH_ERROR), 401

        row = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username.lower(),)
        ).fetchone()
        stored = row[0] if row else DUMMY_HASH
        ok = check_password_hash(stored, password) and row is not None

        if not ok:
            record_failure(key)
            return jsonify(error=GENERIC_AUTH_ERROR), 401  # same message either way

        failures.pop(key, None)
        session.clear()                      # new session on login (anti-fixation)
        session.permanent = True
        session["user"] = username.lower()
        session["last_seen"] = time.time()
        return jsonify(message="Logged in.")

    @app.before_request
    def enforce_idle_timeout():
        if "user" in session:
            if time.time() - session.get("last_seen", 0) > IDLE_TIMEOUT_SEC:
                session.clear()
            else:
                session["last_seen"] = time.time()

    @app.get("/profile")
    def profile():
        if "user" not in session:
            return jsonify(error="Authentication required."), 401
        return jsonify(user=session["user"])

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(message="Logged out.")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    app.failures = failures  # exposed for tests
    return app


if __name__ == "__main__":
    # Bind to localhost only - this lab must not be exposed to a network.
    create_app("users.db").run(host="127.0.0.1", port=5000, debug=False)
