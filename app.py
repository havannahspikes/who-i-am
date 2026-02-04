

#!/usr/bin/env python3
"""
Full app.py with defensive GitHub-backed optional sync for the whoiam.db file.

Preserves:
- alpha (login/register/forgot/reset)
- life (public "life" page with uploads listing & search)
- heartbeat (admin dashboard)
- upload / download / delete / profile update flows

Added:
- /pulse_receiver endpoint (POST/GET) to accept pulses
- pulses table + profile.last_pulse migration
- defensive requests import + github guards
- OPTIONAL outbound auto-pinger (random interval between MIN_INTERVAL and MAX_INTERVAL seconds)
"""
import os
import sqlite3
import mimetypes
import base64
import json
import time
import random
import threading
import sys
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_from_directory, flash, g, abort, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# safe requests import — app can start if requests is missing
try:
    import requests
except Exception:
    requests = None
    print("Warning: 'requests' package not available. GitHub sync disabled.")

# -------------------------
# Configuration
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("LOCAL_DB_PATH", os.path.join(BASE_DIR, "whoiam.db"))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXT = {"pdf", "doc", "docx", "txt", "pptx", "xlsx"}

# Optional pulse secret (if set, inbound pulses must include header X-PULSE-TOKEN or ?token=...)
PULSE_SECRET = os.environ.get("PULSE_SECRET")

# Outbound (this app -> other service) pinger config (optional)
OUTBOUND_TARGET = os.environ.get("OUTBOUND_TARGET", "https://breathe-5006.onrender.com/receive_pulse")
OUTBOUND_PULSE_TOKEN = os.environ.get("OUTBOUND_PULSE_TOKEN")  # header X-PULSE-TOKEN when pinging
OUTBOUND_AUTO_PING = os.environ.get("OUTBOUND_AUTO_PING", "false").lower() in ("1", "true", "yes")
try:
    MIN_INTERVAL = float(os.environ.get("MIN_INTERVAL", "15"))
    MAX_INTERVAL = float(os.environ.get("MAX_INTERVAL", "45"))
except Exception:
    MIN_INTERVAL = 15.0
    MAX_INTERVAL = 45.0

if MIN_INTERVAL <= 0 or MAX_INTERVAL <= 0 or MIN_INTERVAL > MAX_INTERVAL:
    MIN_INTERVAL = 15.0
    MAX_INTERVAL = 45.0

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_a_random_value")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# GitHub sync config (optional)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")  # format owner/repo
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
GITHUB_DB_PATH = os.environ.get("GITHUB_DB_PATH", "whoiam.db")
GITHUB_API_ROOT = "https://api.github.com"

# session for outbound requests (if requests available)
out_session = requests.Session() if requests else None

def log(*a, **k):
    print(*a, **k)
    sys.stdout.flush()

# -------------------------
# DB helpers + migration
# -------------------------
def get_db():
    if getattr(g, "_db", None) is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g._db = conn
    return g._db

@app.teardown_appcontext
def close_db(exc=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

def table_columns(table):
    db = get_db()
    cur = db.execute(f"PRAGMA table_info({table})")
    cols = {row["name"] for row in cur.fetchall()}
    return cols

def add_column_if_missing(table, column_def):
    col_name, sql_def = column_def
    cols = table_columns(table)
    if col_name not in cols:
        db = get_db()
        db.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {sql_def}")
        db.commit()

def init_db_and_migrate():
    db = get_db()
    # users
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            sec_question TEXT,
            sec_answer_hash TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # uploads (base)
    db.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT,
            uploader TEXT
        )
    """)
    # profile single-row config
    db.execute("""
        CREATE TABLE IF NOT EXISTS profile (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            name TEXT,
            tagline TEXT,
            location TEXT,
            contact_email TEXT,
            github TEXT,
            linkedin TEXT,
            portfolio TEXT,
            quick_facts TEXT
        )
    """)
    # pulses table (new) — stores received pulses for auditing
    db.execute("""
        CREATE TABLE IF NOT EXISTS pulses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            payload TEXT,
            received_at TEXT
        )
    """)
    db.commit()

    # add missing uploads columns
    columns = [
        ("mime", "TEXT DEFAULT NULL"),
        ("size", "INTEGER DEFAULT 0"),
        ("description", "TEXT DEFAULT NULL"),
        ("tags", "TEXT DEFAULT NULL"),
        ("uploaded_at", "TEXT DEFAULT NULL"),
        ("downloads", "INTEGER DEFAULT 0")
    ]
    for col in columns:
        add_column_if_missing("uploads", col)

    # add last_pulse column to profile if missing (new)
    add_column_if_missing("profile", ("last_pulse", "TEXT DEFAULT NULL"))

    # default profile row if missing
    cur = db.execute("SELECT COUNT(*) as c FROM profile")
    r = cur.fetchone()
    if not r or r["c"] == 0:
        db.execute(
            "INSERT INTO profile (id, name, tagline, location, contact_email, github, linkedin, portfolio, quick_facts) VALUES (?,?,?,?,?,?,?,?,?)",
            (1, "Your Name", "Developer • IT • Cybersecurity", "City, Country", "you@example.com",
             "https://github.com/yourusername", "https://linkedin.com/in/yourprofile", "https://yourportfolio.example.com",
             "Degree: BSc Computer Science; Skills: Python, JS, Linux, SQL")
        )
        db.commit()

    # set uploaded_at for legacy rows
    db.execute("UPDATE uploads SET uploaded_at = ? WHERE uploaded_at IS NULL", (datetime.utcnow().isoformat(),))
    db.commit()

# -------------------------
# GitHub sync helpers (defensive)
# -------------------------
def github_enabled():
    # require requests package + env vars
    return bool(requests and GITHUB_TOKEN and GITHUB_REPO)

def github_get_file_info(path):
    """
    Return dict {'sha':..., 'content':bytes} if file exists, else None.
    Defensive: returns None if github sync is disabled.
    """
    if not github_enabled():
        return None

    url = f"{GITHUB_API_ROOT}/repos/{GITHUB_REPO}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    params = {"ref": GITHUB_BRANCH}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
    except Exception as e:
        print("GitHub get file error:", e)
        return None
    if r.status_code == 200:
        data = r.json()
        sha = data.get("sha")
        content_b64 = data.get("content", "")
        try:
            raw = base64.b64decode(content_b64) if content_b64 else None
        except Exception:
            raw = None
        return {"sha": sha, "content": raw}
    return None

def github_download_db_if_missing():
    """
    Download whoiam.db from GitHub into DB_PATH only if local DB is missing or empty.
    Returns True if downloaded, False otherwise.
    """
    if not github_enabled():
        # GitHub sync disabled (either requests missing or env vars not set)
        print("GitHub sync disabled; skipping download.")
        return False
    if os.path.exists(DB_PATH) and os.path.getsize(DB_PATH) > 0:
        # preserve local DB
        print("Local DB present; skipping GitHub download.")
        return False
    info = github_get_file_info(GITHUB_DB_PATH)
    if not info or not info.get("content"):
        print("GitHub DB not found or empty.")
        return False
    try:
        with open(DB_PATH, "wb") as f:
            f.write(info["content"])
        print("Downloaded whoiam.db from GitHub.")
        return True
    except Exception as e:
        print("Failed to write DB from GitHub:", e)
        return False

def github_upload_db(commit_message="Update whoiam.db from app"):
    """
    Create/update whoiam.db in the repo. Returns True on success.
    Defensive: returns False if sync not enabled or an error occurs.
    """
    if not github_enabled():
        print("GitHub sync disabled; skipping upload.")
        return False
    if not os.path.exists(DB_PATH):
        print("No local DB to upload.")
        return False

    try:
        with open(DB_PATH, "rb") as f:
            content = f.read()
    except Exception as e:
        print("Unable to read local DB for upload:", e)
        return False

    b64 = base64.b64encode(content).decode("utf-8")
    url = f"{GITHUB_API_ROOT}/repos/{GITHUB_REPO}/contents/{GITHUB_DB_PATH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}

    # get sha if existing
    try:
        r = requests.get(url, headers=headers, params={"ref": GITHUB_BRANCH}, timeout=15)
    except Exception as e:
        print("GitHub get for upload failed:", e)
        return False

    sha = None
    if r.status_code == 200:
        try:
            sha = r.json().get("sha")
        except Exception:
            sha = None

    payload = {
        "message": commit_message,
        "content": b64,
        "branch": GITHUB_BRANCH
    }
    if sha:
        payload["sha"] = sha

    try:
        put_r = requests.put(url, headers=headers, data=json.dumps(payload), timeout=30)
    except Exception as e:
        print("GitHub upload exception:", e)
        return False

    if put_r.status_code in (200, 201):
        print("Uploaded whoiam.db to GitHub:", put_r.status_code)
        return True
    else:
        print("Failed to upload DB to GitHub:", put_r.status_code, put_r.text)
        return False

# -------------------------
# Initialize DB and optionally download from GitHub
# -------------------------
with app.app_context():
    init_db_and_migrate()
    # Attempt to download DB from GitHub only if local missing
    try:
        github_download_db_if_missing()
    except Exception as e:
        print("GitHub download check failed:", e)

# -------------------------
# Utilities (app logic)
# -------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def user_count():
    db = get_db()
    r = db.execute("SELECT COUNT(*) as c FROM users").fetchone()
    return r["c"] if r else 0

def get_user(username):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

def get_upload_by_filename(filename):
    db = get_db()
    return db.execute("SELECT * FROM uploads WHERE filename = ?", (filename,)).fetchone()

def get_upload_by_id(upload_id):
    db = get_db()
    return db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()

def get_profile():
    db = get_db()
    return db.execute("SELECT * FROM profile WHERE id = 1").fetchone()

# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("life"))
    return redirect(url_for("alpha"))

@app.route("/alpha", methods=["GET", "POST"])
def alpha():
    users_exist = user_count() > 0
    hide_register = False

    if request.method == "POST":
        action = request.form.get("action")
        if action == "login":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_user(username)
            if user and check_password_hash(user["password_hash"], password):
                session["username"] = username
                session["is_admin"] = bool(user["is_admin"])
                flash("Welcome back!", "success")
                return redirect(url_for("heartbeat") if session.get("is_admin") else url_for("life"))
            flash("Invalid username or password", "danger")

        elif action == "register":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            sec_q = request.form.get("sec_question", "").strip()
            sec_a = request.form.get("sec_answer", "")
            if not username or not password:
                flash("Choose a username and password", "warning")
            else:
                try:
                    is_admin = 1 if user_count() == 0 else 0
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (username, password_hash, sec_question, sec_answer_hash, is_admin) VALUES (?,?,?,?,?)",
                        (
                            username,
                            generate_password_hash(password),
                            sec_q,
                            generate_password_hash(sec_a or ""),
                            is_admin,
                        ),
                    )
                    db.commit()
                    # Optionally push DB to GitHub to persist user creation
                    if github_enabled():
                        try:
                            github_upload_db(f"Add user {username}")
                        except Exception as e:
                            print("GitHub upload after register failed:", e)
                    if is_admin:
                        flash("Account created — you are the first user and have been made an admin.", "success")
                    else:
                        flash("Account created. You may now login.", "success")
                    return redirect(url_for("alpha"))
                except sqlite3.IntegrityError:
                    flash("Username already exists", "danger")

        elif action == "forgot":
            username = request.form.get("username", "").strip()
            answer = request.form.get("sec_answer", "")
            user = get_user(username)
            if user and user["sec_answer_hash"]:
                if check_password_hash(user["sec_answer_hash"], answer or ""):
                    session["reset_user"] = username
                    flash("Answer accepted — set new password below.", "info")
                else:
                    flash("Incorrect username or security answer", "danger")
            else:
                flash("Incorrect username or security answer", "danger")

        elif action == "reset":
            if "reset_user" not in session:
                flash("No reset in progress", "warning")
            else:
                newpw = request.form.get("new_password", "")
                if not newpw:
                    flash("Please provide a new password", "warning")
                else:
                    db = get_db()
                    db.execute(
                        "UPDATE users SET password_hash = ? WHERE username = ?",
                        (generate_password_hash(newpw), session["reset_user"]),
                    )
                    db.commit()
                    # optional backup
                    if github_enabled():
                        try:
                            github_upload_db(f"Password reset for {session.get('reset_user')}")
                        except Exception as e:
                            print("GitHub upload after reset failed:", e)
                    session.pop("reset_user", None)
                    flash("Password updated — please login.", "success")
                    return redirect(url_for("alpha"))

    return render_template("alpha.html", hide_register=hide_register, users_exist=(user_count() > 0))

@app.route("/life")
def life():
    profile = get_profile()
    q = request.args.get("q", "").strip()
    tag = request.args.get("tag", "").strip()

    db = get_db()
    sql = "SELECT * FROM uploads"
    params = []
    where = []
    if q:
        where.append("(original_name LIKE ? OR description LIKE ? OR tags LIKE ?)")
        likeq = f"%{q}%"
        params.extend([likeq, likeq, likeq])
    if tag:
        where.append("tags LIKE ?")
        params.append(f"%{tag}%")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY uploaded_at DESC"
    cur = db.execute(sql, tuple(params))
    uploads = cur.fetchall()
    logged_in = "username" in session
    return render_template("life.html", profile=profile, uploads=uploads, logged_in=logged_in, query=q, tag=tag)

# Admin: upload doc/publish to life
@app.route("/admin/upload", methods=["POST"])
def admin_upload():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("alpha"))

    if "doc" not in request.files:
        flash("No file part", "warning")
        return redirect(url_for("heartbeat"))

    file = request.files["doc"]
    if file.filename == "":
        flash("No selected file", "warning")
        return redirect(url_for("heartbeat"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        counter = 1
        while os.path.exists(saved_path):
            filename = f"{base}_{counter}{ext}"
            saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            counter += 1
        file.save(saved_path)

        mime, _ = mimetypes.guess_type(saved_path)
        size = os.path.getsize(saved_path)
        description = (request.form.get("description") or "").strip()
        tags = (request.form.get("tags") or "").strip()
        uploaded_at = datetime.utcnow().isoformat()

        db = get_db()
        db.execute(
            "INSERT INTO uploads (filename, original_name, uploader, mime, size, description, tags, uploaded_at, downloads) VALUES (?,?,?,?,?,?,?,?,?)",
            (filename, file.filename, session.get("username"), mime, size, description, tags, uploaded_at, 0),
        )
        db.commit()

        # Upload DB snapshot to GitHub (best-effort)
        if github_enabled():
            try:
                github_upload_db("Publish document to life page")
            except Exception as e:
                print("GitHub upload after admin_upload failed:", e)

        flash("Document uploaded and published to the life page.", "success")
    else:
        flash("File type not allowed.", "danger")
    return redirect(url_for("heartbeat"))

@app.route("/admin/update_profile", methods=["POST"])
def admin_update_profile():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("alpha"))

    name = request.form.get("name", "").strip()
    tagline = request.form.get("tagline", "").strip()
    location = request.form.get("location", "").strip()
    contact_email = request.form.get("contact_email", "").strip()
    github = request.form.get("github", "").strip()
    linkedin = request.form.get("linkedin", "").strip()
    portfolio = request.form.get("portfolio", "").strip()
    quick_facts = request.form.get("quick_facts", "").strip()

    db = get_db()
    db.execute(
        "UPDATE profile SET name=?, tagline=?, location=?, contact_email=?, github=?, linkedin=?, portfolio=?, quick_facts=? WHERE id = 1",
        (name, tagline, location, contact_email, github, linkedin, portfolio, quick_facts)
    )
    db.commit()
    # push to GitHub
    if github_enabled():
        try:
            github_upload_db("Update public profile")
        except Exception as e:
            print("GitHub upload after profile update failed:", e)
    flash("Profile updated — changes will appear on the life page.", "success")
    return redirect(url_for("heartbeat"))

# Download routes
@app.route("/download/<int:upload_id>")
def download_by_id(upload_id):
    up = get_upload_by_id(upload_id)
    if not up:
        abort(404)
    db = get_db()
    db.execute("UPDATE uploads SET downloads = downloads + 1 WHERE id = ?", (upload_id,))
    db.commit()
    return send_from_directory(app.config["UPLOAD_FOLDER"], up["filename"], as_attachment=True)

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    up = get_upload_by_filename(filename)
    if up:
        db = get_db()
        db.execute("UPDATE uploads SET downloads = downloads + 1 WHERE id = ?", (up["id"],))
        db.commit()
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

@app.route("/heartbeat")
def heartbeat():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("alpha"))
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
    uploads = db.execute("SELECT * FROM uploads ORDER BY uploaded_at DESC").fetchall()
    profile = get_profile()
    return render_template("heartbeat.html", users=users, uploads=uploads, profile=profile)

@app.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("alpha"))
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    if github_enabled():
        try:
            github_upload_db(f"Delete user {user_id}")
        except Exception as e:
            print("GitHub upload after delete_user failed:", e)
    flash("User deleted", "info")
    return redirect(url_for("heartbeat"))

@app.route("/delete_upload/<int:upload_id>", methods=["POST"])
def delete_upload(upload_id):
    up = get_upload_by_id(upload_id)
    if not up:
        flash("Upload not found", "warning")
        return redirect(url_for("heartbeat"))
    if "username" not in session:
        flash("Please sign in", "warning")
        return redirect(url_for("alpha"))
    if session.get("username") != up["uploader"] and not session.get("is_admin"):
        flash("Admin access required or you must be the uploader", "danger")
        return redirect(url_for("heartbeat"))

    try:
        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], up["filename"]))
    except Exception:
        pass

    db = get_db()
    db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
    db.commit()
    # push DB to GitHub
    if github_enabled():
        try:
            github_upload_db(f"Delete upload {upload_id}")
        except Exception as e:
            print("GitHub upload after delete_upload failed:", e)

    flash("Upload deleted", "info")
    return redirect(url_for("heartbeat") if session.get("is_admin") else url_for("life"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("alpha"))

# -------------------------
# PULSE RECEIVER PLACEHOLDER (new)
# -------------------------
@app.route("/pulse_receiver", methods=["POST", "GET"])
def pulse_receiver():
    """
    Accepts pulses from external services.
    - If PULSE_SECRET env var is set, requires header X-PULSE-TOKEN or ?token=... to match.
    - Stores the pulse in `pulses` table and updates profile.last_pulse.
    - Returns JSON {status, received_at}.
    """
    # secret check (optional)
    token = request.headers.get("X-PULSE-TOKEN") or request.args.get("token")
    if PULSE_SECRET:
        if not token or token != PULSE_SECRET:
            return jsonify({"status":"unauthorized"}), 401

    # get payload (JSON preferred)
    payload = request.get_json(silent=True)
    if payload is None:
        # fallback to form or a minimal payload
        payload = request.form.to_dict() or {"message": "ping"}

    received_at = datetime.utcnow().isoformat()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO pulses (source, payload, received_at) VALUES (?, ?, ?)",
            (request.remote_addr or "unknown", json.dumps(payload), received_at)
        )
        db.execute("UPDATE profile SET last_pulse = ? WHERE id = 1", (received_at,))
        db.commit()
    except Exception as e:
        print("Error saving pulse:", e)

    # Optional: forward to BREATH_URL if configured (best-effort)
    BREATH_URL = os.environ.get("BREATH_URL")
    BREATH_TOKEN = os.environ.get("BREATH_TOKEN")
    if BREATH_URL and requests:
        try:
            headers = {}
            if BREATH_TOKEN:
                headers["X-PULSE-TOKEN"] = BREATH_TOKEN
            post_session = out_session if out_session else requests
            try:
                post_session.post(BREATH_URL, json={"from": "whoiam", "status": "alive", "received_at": received_at}, headers=headers, timeout=10)
                log(f"Forwarded pulse to {BREATH_URL}")
            except Exception as e:
                print("Forward to breathe failed:", e)
        except Exception as e:
            print("Forward to breathe failed:", e)

    # Optional: trigger GitHub backup (best-effort) — commented out by default
    # if github_enabled():
    #     try:
    #         github_upload_db("Pulse received — update DB")
    #     except Exception as e:
    #         print("GitHub upload after pulse failed:", e)

    return jsonify({"status":"ok", "received_at": received_at})

# -------------------------
# Outbound auto-pinger (optional)
# -------------------------
def outbound_pinger_loop():
    """
    Post a small pulse to OUTBOUND_TARGET at random intervals between MIN_INTERVAL and MAX_INTERVAL.
    Adds header X-PULSE-TOKEN if OUTBOUND_PULSE_TOKEN is present.
    """
    if not out_session:
        log("outbound_pinger: requests not available; pinger disabled")
        return
    log(f"outbound_pinger: starting (target={OUTBOUND_TARGET}, intervals {MIN_INTERVAL}-{MAX_INTERVAL}s)")
    while True:
        wait = random.uniform(MIN_INTERVAL, MAX_INTERVAL)
        log(f"outbound_pinger: sleeping {wait:.2f}s")
        time.sleep(wait)
        payload = {"source": "whoiam", "timestamp": datetime.utcnow().isoformat()}
        headers = {}
        if OUTBOUND_PULSE_TOKEN:
            headers["X-PULSE-TOKEN"] = OUTBOUND_PULSE_TOKEN
        try:
            r = out_session.post(OUTBOUND_TARGET, json=payload, headers=headers, timeout=10)
            log(f"outbound_pinger: POST {OUTBOUND_TARGET} -> {r.status_code}")
        except Exception as e:
            log("outbound_pinger: POST error:", e)

# start outbound pinger if enabled
if OUTBOUND_AUTO_PING:
    t_out = threading.Thread(target=outbound_pinger_loop, name="outbound_pinger", daemon=True)
    t_out.start()
else:
    log("outbound_pinger: disabled (set OUTBOUND_AUTO_PING=true to enable)")

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # In production, use gunicorn as you do. This runs a dev server when executed directly.
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
