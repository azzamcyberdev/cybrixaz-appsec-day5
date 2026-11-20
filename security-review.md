# Application Security Review: Flask Baseline Application

**Target System**: `day-5/sandbox/app.py`  
**Test Environment**: Isolated Sandbox (`127.0.0.1:5070`), SQLite (`day-5/sandbox/appsec.db`), Python 3.12 (PowerShell 5.1)  
**Verification Method**: Controlled dynamic testing via automated runner (`run_checks.py`), debug disabled (`debug=False`)

---

## 1. Executive Summary

A targeted application security review and dynamic verification suite were executed against `day-5/sandbox/app.py` on `127.0.0.1:5070`. The application serves both HTML views and JSON REST endpoints for user authentication, note management, and profile updates.

- **Defensive Baseline**: Authentication and data persistence consistently utilize SQLite parameterized queries (`?` placeholders). Injection attempts failed cleanly without authentication bypass or syntax leakage. Passwords use PBKDF2/scrypt cryptographic hashing.
- **Confirmed Vulnerabilities**: Real exposures were verified across data access controls, cross-site request forgery, session lifecycle management, and runtime configurations. Notably, default Flask session cookies are **signed (integrity-checked, not encrypted)** and **lack server-side revocation**, allowing post-logout session replay.

---

## 2. Findings Matrix

| Ref | Vulnerability Finding | Severity | Affected Component | Status | Summary |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **SEC-01** | SQL Injection Defense | **None** | `POST /login`, `POST /register`, `POST /dashboard` | **Defended** | Parameterized queries prevented all SQL syntax injection and auth bypass. |
| **SEC-02** | Excessive Data Exposure | **Medium** | `GET /api/data`, `GET /dashboard` | **Confirmed** | Full user directory (`id`, `username`, `created_at`) exposed to standard users. |
| **SEC-03** | Missing Anti-CSRF Protection | **Medium** | `POST /dashboard`, `POST /profile`, `POST /register` | **Confirmed** | State changes rely solely on ambient cookies without unpredictable request tokens. |
| **SEC-04** | Stateless Session Cookie Replay | **Medium** | `GET /logout`, `GET /api/data`, `GET /profile` | **Confirmed** | Default Flask cookies are signed (not encrypted) and lack server revocation. |
| **SEC-05** | Public Bind & Debug Mode | **Low** | Main entrypoint (`host="0.0.0.0"`, `debug=True`) | **Confirmed** | Exposes service to external interfaces; Werkzeug debugger active if triggered. |
| **SEC-06** | Missing Strict Cookie Flags | **Low** | `app.config` session defaults | **Confirmed** | `SESSION_COOKIE_SAMESITE` and `SESSION_COOKIE_SECURE` are unconfigured defaults. |

---

## 3. Why SQLi Login Payloads Failed (Parameterized `?` Queries)

During testing on `127.0.0.1:5070`, classic SQL injection payloads were submitted to `POST /login` via JSON and URL-encoded form data:
- `' OR '1'='1`
- `admin'--`
- `' OR 1=1--`
- `" OR ""="`

### Technical Root Cause of Defense
All payloads were cleanly rejected with **HTTP 401 Unauthorized** (`{"error": "Invalid username or password."}`) or re-rendered `login.html` with a generic flash error. Zero authentication bypass occurred and no database syntax errors (HTTP 500) were produced.

```python
# app.py lines 134-137
user = db.execute(
    "SELECT id, username, password_hash FROM users WHERE username = ?",
    (username,),
).fetchone()
```

1. **AST Separation of Code and Data**: SQLite compiles the SQL query abstract syntax tree (AST) *before* binding variables. The placeholder `?` defines a literal data slot.
2. **Literal Value Matching**: The payload `' OR '1'='1` is evaluated strictly as literal character data against `users.username`. Because no database account has that literal username, `fetchone()` returns `None`.
3. **Safe Evaluation**: The check `if not user or not check_password_hash(...)` safely exits via the failure branch without executing downstream logic.

---

## 4. Confirmed Exposures & Vulnerability Details

### 1. User Directory Exposure (`GET /dashboard` & `GET /api/data`)
- **Observation**: `GET /api/data` returns `stored_users` containing all user records in the database (`['day3user', 'mazza']`). `GET /dashboard` renders an HTML table titled `Stored Users (users table)` displaying every user's ID, username, and registration timestamp to any logged-in user.
- **Impact**: Violates the Principle of Least Privilege. Standard authenticated users can enumerate the full system directory for targeted phishing or credential stuffing.

### 2. Missing Anti-CSRF Protection on State-Changing POST Routes
- **Observation**: `POST /dashboard`, `POST /profile`, and `POST /register` accept state-modifying requests without validating an anti-CSRF token (`_csrf_token`).
- **Impact**: State changes rely entirely on ambient browser cookies. While modern browsers apply default `SameSite=Lax` restrictions, relying on browser defaults alone weakens defense-in-depth across cross-subdomain interactions, older clients, or top-level transitions.

### 3. Post-Logout Session Replay on Stateless Flask Cookies
- **Observation**: When a user logs out (`GET /logout`), the application issues an empty `Set-Cookie: session=; Expires=...`. However, when a previously issued session cookie (`session=<redacted>`) was retained and replayed against `GET /api/data`, the server returned **HTTP 200 OK** with full profile access.
- **Impact**: **Default Flask session cookies are signed (integrity-checked, not encrypted) and lack server-side revocation**. Because the server stores no session registry or token version state in the database, any signed cookie remains valid until its timestamp expires, regardless of user logout.

### 4. Insecure Production Bind & Debugger (`host="0.0.0.0"` + `debug=True`)
- **Observation**: Line 332 specifies `app.run(host="0.0.0.0", port=int(os.getenv("PORT", 3000)), debug=True)`.
- **Impact**: Binds to all network interfaces (including public/LAN adapters). Running with `debug=True` in production risks exposing Werkzeug's interactive traceback pages, leaking local filesystem paths, variables, and framework versions.

---

## 5. Prioritized Fixes

### Phase 1: Immediate Hotfixes (Configuration & Authorization)
1. **Harden Network Bind & Debug Flag**:
   ```python
   debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1")
   app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 3000)), debug=debug_mode)
   ```
2. **Remove User Directory Query**: Delete `SELECT ... FROM users ORDER BY id DESC` from `dashboard()` and `api_data()`. Restrict user queries strictly to the authenticated `session["user_id"]`.
3. **Configure Explicit Session Cookie Flags**:
   ```python
   app.config.update(
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SAMESITE="Lax",
       SESSION_COOKIE_SECURE=os.getenv("ENV") == "production",
   )
   ```

### Phase 2: Architectural Hardening (Tokens & Session Lifecycle)
1. **Implement Anti-CSRF Tokens**: Integrate `flask_wtf.csrf.CSRFProtect` to enforce synchronized CSRF token validation on all state-changing endpoints (`POST`, `PUT`, `DELETE`).
2. **Implement Server-Side Session Revocation**: Add a `token_version` column to `users`. Store `session["token_version"] = user["token_version"]`. On logout or password reset, increment `token_version` in SQLite, instantly invalidating all historical client session cookies.
3. **Eliminate Timing Enumeration**: Pre-compute a dummy cryptographic password hash so authentication lookups for non-existent users incur identical hash verification latency.
