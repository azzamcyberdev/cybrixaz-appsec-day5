import os
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())
DATABASE = os.getenv("DATABASE_PATH", "appsec.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        # Enforce foreign key constraints in SQLite
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                user_id INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
                display_name TEXT NOT NULL DEFAULT '',
                bio TEXT NOT NULL DEFAULT '',
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        db.commit()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.get_json(silent=True) if request.is_json else request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if not username or len(username) < 3:
            err = "Username must be at least 3 characters."
            return (jsonify({"error": err}), 400) if request.is_json else (flash(err, "error") or render_template("register.html"))

        if not password or len(password) < 6:
            err = "Password must be at least 6 characters."
            return (jsonify({"error": err}), 400) if request.is_json else (flash(err, "error") or render_template("register.html"))

        db = get_db()
        # Secure password hashing via pbkdf2:sha256 / scrypt default
        password_hash = generate_password_hash(password)

        try:
            # Parameterized query to avoid SQL injection
            cursor = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            db.commit()
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            err = "Username already exists."
            return (jsonify({"error": err}), 409) if request.is_json else (flash(err, "error") or render_template("register.html"))

        if request.is_json:
            return jsonify({"status": "registered", "user": {"id": user_id, "username": username}}), 201

        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json(silent=True) if request.is_json else request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Constant-time comparison check
        if not user or not check_password_hash(user["password_hash"], password):
            err = "Invalid username or password."
            return (jsonify({"error": err}), 401) if request.is_json else (flash(err, "error") or render_template("login.html"))

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        if request.is_json:
            return jsonify({"status": "authenticated", "user": {"id": user["id"], "username": user["username"]}}), 200

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    if request.is_json:
        return jsonify({"status": "logged_out"}), 200
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        data = request.get_json(silent=True) if request.is_json else request.form
        content = (data.get("content") or "").strip()

        if not content:
            err = "Note content cannot be empty."
            return (jsonify({"error": err}), 400) if request.is_json else (flash(err, "error") or redirect(url_for("dashboard")))

        # Scoped strictly by session user_id to prevent IDOR / privilege escalation
        cursor = db.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)",
            (user_id, content),
        )
        db.commit()

        if request.is_json:
            return jsonify({
                "status": "created",
                "note": {"id": cursor.lastrowid, "user_id": user_id, "content": content}
            }), 201

        flash("Note saved.", "success")
        return redirect(url_for("dashboard"))

    # GET: Scoped strictly by session user_id
    current_user = db.execute(
        "SELECT id, username, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    user_notes = db.execute(
        "SELECT id, content, created_at FROM notes WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()

    all_users = db.execute(
        "SELECT id, username, created_at FROM users ORDER BY id DESC"
    ).fetchall()

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({
            "user": dict(current_user),
            "notes": [dict(n) for n in user_notes]
        })

    return render_template("dashboard.html", user=current_user, notes=user_notes, all_users=all_users)


def parse_profile_payload():
    data = request.get_json(silent=True) if request.is_json else request.form
    if not hasattr(data, "get"):
        raise ValueError("Request body must be a JSON object or form data.")
    out = []
    for key in ("display_name", "bio"):
        value = data.get(key, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string.")
        out.append(value.strip())
    return tuple(out)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        try:
            display_name, bio = parse_profile_payload()
        except ValueError as e:
            err = str(e)
            if request.is_json or request.headers.get("Accept") == "application/json":
                return jsonify({"error": err}), 400
            flash(err, "error")
            return redirect(url_for("profile"))

        if len(display_name) > 50:
            err = "Display name cannot exceed 50 characters."
            if request.is_json or request.headers.get("Accept") == "application/json":
                return jsonify({"error": err}), 400
            flash(err, "error")
            return redirect(url_for("profile"))

        if len(bio) > 500:
            err = "Bio cannot exceed 500 characters."
            if request.is_json or request.headers.get("Accept") == "application/json":
                return jsonify({"error": err}), 400
            flash(err, "error")
            return redirect(url_for("profile"))

        # Parameterized upsert strictly bound to session["user_id"]
        db.execute(
            """
            INSERT INTO profiles (user_id, display_name, bio, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                display_name = excluded.display_name,
                bio = excluded.bio,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, display_name, bio),
        )
        db.commit()

        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"status": "saved", "display_name": display_name, "bio": bio}), 200

        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    # GET: Single parameterized query joining users and profiles with note count subquery
    profile_row = db.execute(
        """
        SELECT
            u.id,
            u.username,
            u.created_at,
            COALESCE(p.display_name, '') AS display_name,
            COALESCE(p.bio, '') AS bio,
            COALESCE(p.updated_at, '') AS updated_at,
            (SELECT COUNT(*) FROM notes n WHERE n.user_id = u.id) AS note_count
        FROM users u
        LEFT JOIN profiles p ON u.id = p.user_id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()

    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({
            "status": "ok",
            "profile": dict(profile_row) if profile_row else None
        }), 200

    return render_template("profile.html", profile=profile_row)


@app.route("/api/data")
@login_required
def api_data():
    db = get_db()
    user = db.execute(
        "SELECT id, username, created_at FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

    all_users = db.execute(
        "SELECT id, username, created_at FROM users ORDER BY id DESC"
    ).fetchall()

    return jsonify({
        "status": "ok",
        "current_user": dict(user),
        "stored_users": [dict(u) for u in all_users]
    })


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 3000)), debug=True)
