# Day 5 AppSec Snippet Exercises & Answer Key

This document contains 3 realistic code review snippet exercises reflecting common web application security vulnerabilities. Each exercise includes a scenario, a vulnerable code snippet, analysis questions, and a comprehensive answer key with production-grade remediations.

---

## Exercise 1: Authentication Bypass, SQL Injection & Timing Side-Channel

### Scenario
An internal developer has written a custom authentication endpoint in Flask for an enterprise portal. The developer noticed SQL errors during testing and attempted to sanitize inputs manually, but concerns remain regarding injection and user enumeration.

### Vulnerable Code Snippet
```python
import sqlite3
from flask import Flask, request, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "insecure-default-key"

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    # Attempted "sanitization" by stripping single quotes
    sanitized_user = username.replace("'", "")
    
    # Raw SQL formatting
    query = f"SELECT id, username, password_hash FROM users WHERE username = '{sanitized_user}'"
    user = db.execute(query).fetchone()

    # Early exit if user does not exist
    if not user:
        return jsonify({"error": "User does not exist"}), 404

    # Cryptographic hash verification only executed if user exists
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect password"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"status": "authenticated"}), 200
```

### Questions
1. **Injection Analysis**: Why is `replace("'", "")` insufficient to prevent SQL injection in general, and what happens if the query structure or database dialect changes (e.g. numeric fields, backslash escaping)?
2. **Enumeration & Timing**: Identify the two distinct ways an attacker can enumerate valid usernames using this endpoint.
3. **Remediation**: Provide the fully refactored, hardened implementation that eliminates SQL injection and timing side-channels.

---

### Exercise 1 Answer Key

#### 1. Flaws in Blacklist Sanitization
- **Blacklist Incompleteness**: Stripping `'` fails if the SQL engine accepts alternative escape characters (e.g. `\`, hex literals, or unicode normalization tricks depending on collation).
- **Type Context Vulnerability**: If the parameter were injected into a numeric field (e.g. `WHERE id = {user_id}`), no quotes are needed to execute a SQL injection payload (e.g. `1 OR 1=1`).
- **Core Principle Violation**: Never attempt to sanitize or filter input for SQL syntax manually. The database driver must treat user input strictly as data, never as executable SQL instructions.

#### 2. User Enumeration & Timing Discrepancy
- **Explicit Error Messages**: The endpoint returns distinct HTTP status codes and error messages:
  - Non-existent user: `HTTP 404 {"error": "User does not exist"}`
  - Existing user with wrong password: `HTTP 401 {"error": "Incorrect password"}`
  An attacker can trivially brute-force user lists by checking for `404` vs `401`.
- **Timing Side-Channel**: Non-existent users exit immediately in a fraction of a millisecond (`< 1ms`). For valid users, the server executes `check_password_hash()`, which runs thousands of iterations of PBKDF2/scrypt taking `50ms - 250ms`. Even if error messages were identical, network latency analysis would reveal valid accounts.

#### 3. Remediated Code
```python
import os
import sqlite3
from flask import Flask, request, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# Precomputed dummy hash for constant-time comparison on non-existent users
DUMMY_HASH = generate_password_hash("dummy-fallback-passphrase-to-prevent-timing-leak")

def get_db():
    conn = sqlite3.connect(os.environ.get("DATABASE_PATH", "users.db"))
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Invalid username or password."}), 401

    db = get_db()
    # Parameterized query: User input is passed as bound parameter tuple
    user = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Prevent timing enumeration: Always execute hash verification
    stored_hash = user["password_hash"] if user else DUMMY_HASH
    is_valid = check_password_hash(stored_hash, password)

    if not user or not is_valid:
        # Uniform status and generic error message for all failure paths
        return jsonify({"error": "Invalid username or password."}), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"status": "authenticated", "user_id": user["id"]}), 200
```

---

## Exercise 2: Broken Object Level Access Control (BOLA/IDOR) & Excessive Data Exposure

### Scenario
A healthcare records application provides an API endpoint for users to retrieve and update medical appointment notes. Developers implemented `@login_required` to ensure that only logged-in users can reach the endpoints, but users are reporting they can view other patients' consultation notes.

### Vulnerable Code Snippet
```python
import sqlite3
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

def get_db():
    conn = sqlite3.connect("health.db")
    conn.row_factory = sqlite3.Row
    return conn

# Vulnerable note lookup endpoint
@app.route("/api/notes/<int:note_id>", methods=["GET"])
@login_required
def get_note(note_id):
    db = get_db()
    # Parameterized query, but missing authorization / ownership check
    note = db.execute(
        "SELECT * FROM notes WHERE id = ?",
        (note_id,)
    ).fetchone()

    if not note:
        return jsonify({"error": "Note not found"}), 404

    # Dumps entire database row including internal fields
    return jsonify(dict(note)), 200

# Vulnerable user directory endpoint
@app.route("/api/users/profile", methods=["GET"])
@login_required
def get_user_profile():
    db = get_db()
    # Intended to fetch current user, but also pulls all system accounts
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    all_users = db.execute("SELECT id, username, email, ssn, role FROM users").fetchall()

    return jsonify({
        "current_user": dict(user),
        "directory": [dict(u) for u in all_users]
    }), 200
```

### Questions
1. **BOLA / IDOR**: What is the root cause of the vulnerability in `GET /api/notes/<note_id>`, and how would an attacker exploit it?
2. **Excessive Data Exposure**: Identify the architectural issue in `SELECT *` and exposing `all_users` via `/api/users/profile`.
3. **Remediation**: Refactor both endpoints to enforce contextual authorization (scoping by `session["user_id"]`) and strict data transfer object (DTO) filtering.

---

### Exercise 2 Answer Key

#### 1. Root Cause of BOLA / IDOR
- **Authentication != Authorization**: The `@login_required` decorator confirms *who* the caller is (identity verification), but does *not* verify whether the caller has permission to view the specific object requested (access control).
- **Exploitation**: An authenticated attacker registered as User A with `session["user_id"] = 10` can sequentially iterate through `GET /api/notes/1`, `GET /api/notes/2`, etc. Because `WHERE id = ?` only filters by the primary key of the note and ignores ownership, the endpoint returns notes belonging to any patient in the system.

#### 2. Excessive Data Exposure
- **Wildcard Queries (`SELECT *`)**: Using `SELECT *` automatically leaks newly added sensitive database columns (e.g. password hashes, reset tokens, internal flags) whenever the schema evolves.
- **Over-Privileged Directory Dump**: Returning the entire `users` table including `ssn`, `role`, and `email` to standard non-admin users violates the Principle of Least Privilege and GDPR/HIPAA compliance requirements.

#### 3. Remediated Code
```python
@app.route("/api/notes/<int:note_id>", methods=["GET"])
@login_required
def get_note(note_id):
    db = get_db()
    user_id = session["user_id"]
    
    # Enforce contextual authorization: Query MUST include user_id filter
    # Explicit column projection: Never use SELECT *
    note = db.execute(
        """
        SELECT id, user_id, title, content, created_at
        FROM notes
        WHERE id = ? AND user_id = ?
        """,
        (note_id, user_id)
    ).fetchone()

    if not note:
        # Return generic 404 to prevent resource existence enumeration
        return jsonify({"error": "Note not found"}), 404

    return jsonify({
        "id": note["id"],
        "title": note["title"],
        "content": note["content"],
        "created_at": note["created_at"]
    }), 200

@app.route("/api/users/profile", methods=["GET"])
@login_required
def get_user_profile():
    db = get_db()
    user_id = session["user_id"]

    # Explicit allowlist of non-sensitive attributes for self-profile
    user = db.execute(
        """
        SELECT id, username, email
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not user:
        return jsonify({"error": "User profile not found"}), 404

    # System directory removed; standard users only receive their own profile
    return jsonify({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"]
        }
    }), 200
```

---

## Exercise 3: Cross-Site Request Forgery (CSRF) & Insecure Session Cookie Attributes

### Scenario
A web application allows users to update their profile email address and biography. The application uses Flask's default session cookies. An external security audit flags the state-changing endpoints for lack of CSRF defenses.

### Vulnerable Code Snippet
```python
from flask import Flask, request, jsonify, session, render_template, redirect, url_for

app = Flask(__name__)
app.secret_key = "super-secret-production-key"

# Insecure cookie settings: Default Flask leaves SameSite=None/Lax and Secure=False
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,     # Transmitted over unencrypted HTTP
    SESSION_COOKIE_SAMESITE=None,    # Sent in all cross-site requests
)

@app.route("/profile/update", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # State change triggered without anti-CSRF token verification
    new_email = request.form.get("email")
    new_bio = request.form.get("bio")

    db = get_db()
    db.execute(
        "UPDATE profiles SET email = ?, bio = ? WHERE user_id = ?",
        (new_email, new_bio, session["user_id"])
    )
    db.commit()

    return "Profile updated successfully."
```

### Questions
1. **CSRF Attack Mechanism**: Provide an HTML proof-of-concept showing how an attacker hosting an external site (`https://evil-attacker.com`) can force an authenticated victim's browser to execute this update.
2. **Cookie Defense In-Depth**: Explain why `HttpOnly=True` does *not* prevent CSRF, and how `SameSite=Lax` or `Strict` and `Secure=True` alter browser transmission behavior.
3. **Remediation**: Show the defense-in-depth remediation implementing anti-CSRF token validation (or SeaSurf/Flask-WTF token pattern) and secure cookie configuration.

---

### Exercise 3 Answer Key

#### 1. Proof-of-Concept Exploit (`attacker_site.html`)
Because the application relies solely on ambient credentials (the browser's stored session cookie) and does not validate an unpredictable request token or enforce strict SameSite policies:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Free Rewards Page</title>
</head>
<body onload="document.forms['csrfForm'].submit()">
  <h3>Claiming your promotional gift card...</h3>
  <!-- Hidden form targeting victim's banking/profile update endpoint -->
  <form id="csrfForm" action="http://target-app.local/profile/update" method="POST">
    <input type="hidden" name="email" value="attacker-controlled-inbox@evil.com" />
    <input type="hidden" name="bio" value="Account hijacked via CSRF" />
  </form>
</body>
</html>
```
When an authenticated user visits `attacker_site.html`, the browser automatically attaches the victim's session cookie to the cross-site `POST` request, silently overwriting their email address.

#### 2. Defense-in-Depth Cookie Analysis
- **`HttpOnly=True` Limitation**: `HttpOnly` blocks client-side JavaScript (`document.cookie`) from reading the cookie, mitigating XSS-based token exfiltration. However, it does *not* prevent the browser from automatically attaching the cookie to cross-origin HTTP requests.
- **`SameSite=Lax` vs. `Strict`**:
  - `SameSite=Strict`: The cookie is never sent in cross-site requests under any circumstance.
  - `SameSite=Lax`: Modern browsers default to Lax for cookies without an explicit attribute. Cookies are withheld on cross-site subrequests (images, iframes) and cross-site `POST` requests, but sent on top-level `GET` navigations. **However**, relying on Lax alone weakens defense-in-depth: GET-based state changes or older browser clients remain vulnerable.
- **`Secure=True`**: Ensures the cookie is only transmitted over TLS/HTTPS encrypted connections, preventing eavesdropping on insecure networks.

#### 3. Remediated Code
```python
import os
import secrets
from flask import Flask, request, jsonify, session, abort, render_template, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Hardened Session Cookie Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Prevent JavaScript access (XSS mitigation)
    SESSION_COOKIE_SECURE=True,         # Only transmit over HTTPS
    SESSION_COOKIE_SAMESITE="Lax",      # Prevent cross-site POST attachment
    PERMANENT_SESSION_LIFETIME=1800,    # 30-minute idle session timeout
)

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def validate_csrf():
    """Verify anti-CSRF token on all state-changing HTTP methods."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        stored_token = session.get("_csrf_token")
        if not stored_token or not token or not secrets.compare_digest(stored_token, token):
            abort(403, description="CSRF token validation failed.")

@app.before_request
def csrf_protect():
    # Enforce CSRF check globally on state-changing methods
    validate_csrf()

@app.route("/profile/update", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Inputs sanitized and validated
    new_email = (request.form.get("email") or "").strip()
    new_bio = (request.form.get("bio") or "").strip()

    if not new_email or "@" not in new_email:
        abort(400, description="Invalid email address.")

    db = get_db()
    db.execute(
        "UPDATE profiles SET email = ?, bio = ? WHERE user_id = ?",
        (new_email, new_bio, session["user_id"])
    )
    db.commit()

    return "Profile updated successfully."
```
```html
<!-- Inside profile.html template -->
<form method="POST" action="{{ url_for('update_profile') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label for="email">Email</label>
  <input type="email" id="email" name="email" value="{{ profile.email }}">
  <button type="submit">Update</button>
</form>
```
