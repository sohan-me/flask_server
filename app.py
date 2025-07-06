from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import hashlib
import json
from flask_cors import CORS
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")

CORS(app)

DB_FILE = "users.json"


# ---------------- Utility Functions ---------------- #
def load_db():
    try:
        with open(DB_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"users": {}, "active": {}, "admin": {}}


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)


def generate_signature(user_data):
    data_str = f"{user_data.get('language','')}{user_data.get('color_depth','')}{user_data.get('device_memory','')}{user_data.get('hardware_concurrency','')}{user_data.get('platform','')}"
    return hashlib.sha256(data_str.encode()).hexdigest()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(stored_hash, provided_password):
    return stored_hash == hash_password(provided_password)


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


# ---------------- Routes ---------------- #

@app.route("/")
def home():
    return redirect(url_for("register_page"))


# Register Page
@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        language = request.form.get("language", "")
        color_depth = request.form.get("color_depth", "")
        screenSize = request.form.get("screenSize", "")
        device_memory = request.form.get("device_memory", "")
        hardware_concurrency = request.form.get("hardware_concurrency", "")
        platform = request.form.get("platform", "")

        if not username:
            return render_template("register.html", message="Username is required!")

        user_data = {
            "username": username,
            "language": language,
            "color_depth": color_depth,
            "screenSize": screenSize,
            "device_memory": device_memory,
            "hardware_concurrency": hardware_concurrency,
            "platform": platform,
        }
        signature = generate_signature(user_data)

        db = load_db()

        if signature in db["users"]:
            return render_template("register.html", message="Browser already registered.")


        db["users"][signature] = {
            **user_data,
            "registered_at": datetime.now().isoformat(),
            "expires": None,
            "active": False,
        }
        db["active"][signature] = False
        save_db(db)
        return render_template("register.html", message="Registration successful! Please contact admin to activate your account.")

    return render_template("register.html", message=None)


# Admin login page
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = load_db()
        stored_hash = db.get("admin", {}).get(username)

        if not stored_hash or not verify_password(stored_hash, password):
            return render_template("admin.html", message="Invalid credentials")

        session["admin_logged_in"] = True
        session["admin_username"] = username
        return redirect(url_for("admin_dashboard"))

    return render_template("admin.html", message=None)


# Admin dashboard - list users
@app.route("/admin/dashboard")
@require_admin
def admin_dashboard():
    db = load_db()
    users_list = []
    for signature, u in db["users"].items():
        users_list.append({
            "username": u.get("username", "N/A"),
            "signature": signature,
            "language": u.get("language", "N/A"),
            "color_depth": u.get("color_depth", "N/A"),
            "device_memory": u.get("device_memory", "N/A"),
            "hardware_concurrency": u.get("hardware_concurrency", "N/A"),
            "platform": u.get("platform", "N/A"),
            "screenSize": u.get("screenSize", "N/A"),
            "created": u.get("registered_at", "N/A"),
            "expires": u.get("expires", "N/A"),
            "active": u.get("active", False),
        })
    return render_template("admin_dashboard.html", users=users_list)


# Admin toggle user active/deactive
@app.route("/admin/toggle/<signature>", methods=["POST"])
def admin_toggle_user(signature):
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    db = load_db()
    if signature not in db["users"]:
        return jsonify({"success": False, "error": "User not found"})

    current_status = db["users"][signature].get("active", False)
    new_status = not current_status
    db["users"][signature]["active"] = new_status
    db["active"][signature] = new_status

    if new_status:
        # Set expiry 1 year from now
        db["users"][signature]["expires"] = (datetime.now() + timedelta(days=365)).isoformat()
    else:
        # Clear expiry on deactivate
        db["users"][signature]["expires"] = None

    save_db(db)
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/remove/<signature>", methods=["POST"])
def admin_remove_user(signature):
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    db = load_db()
    if signature not in db["users"]:
        return jsonify({"success": False, "error": "User not found"})

    # Remove user from both collections
    db["users"].pop(signature, None)
    db["active"].pop(signature, None)
    
    save_db(db)
    return redirect(url_for("admin_dashboard"))


# Admin logout
@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


# Create default admin - run once
@app.route("/create-admin")
def create_admin():
    db = load_db()
    if "admin" not in db or not db["admin"]:
        db["admin"]["admin"] = hash_password("Barhatta&1984")
        save_db(db)
        return "Default admin created (username: admin, password: Barhatta&1984)"
    return "Admin already exists"


# Verify user - check active and expiry
@app.route('/verify', methods=['POST'])
def verify_user():
    user_data = request.json
    signature = generate_signature(user_data)

    db = load_db()

    if signature not in db["users"]:
        return jsonify({"status": "error", "message": "User not registered"}), 404

    user = db["users"][signature]

    if not user.get("active", False):
        return jsonify({"status": "error", "message": "User deactivated"}), 403

    expires = user.get("expires")
    if expires:
        expiry_date = datetime.fromisoformat(expires)
        if expiry_date < datetime.now():
            return jsonify({"status": "error", "message": "User subscription expired"}), 403

    return jsonify({"status": "success", "message": "Access granted"})


# ---------------- Run Server ---------------- #
if __name__ == "__main__":
    app.run(debug=True)