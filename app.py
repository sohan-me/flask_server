from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import hashlib
from flask_cors import CORS
import os
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


CORS(app)
db = SQLAlchemy(app)

# ---------------- Database Models ---------------- #
class User(db.Model):
    __tablename__ = 'users'
    
    signature = db.Column(db.String(255), primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    language = db.Column(db.String(20))
    color_depth = db.Column(db.String(10))
    screen_size = db.Column(db.String(20))
    device_memory = db.Column(db.String(10))
    hardware_concurrency = db.Column(db.String(10))
    platform = db.Column(db.String(50))
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class Admin(db.Model):
    __tablename__ = 'admins'
    
    username = db.Column(db.String(80), primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)

# ---------------- Utility Functions ---------------- #
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

# Initialize database
@app.before_request
def initialize_database():
    db.create_all()

# ---------------- Routes ---------------- #
@app.route("/")
def home():
    return redirect(url_for("register_page"))

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        language = request.form.get("language", "")
        color_depth = request.form.get("color_depth", "")
        screen_size = request.form.get("screenSize", "")
        device_memory = request.form.get("device_memory", "")
        hardware_concurrency = request.form.get("hardware_concurrency", "")
        platform = request.form.get("platform", "")

        if not username:
            return render_template("register.html", message="Username is required!")

        user_data = {
            "username": username,
            "language": language,
            "color_depth": color_depth,
            "screen_size": screen_size,
            "device_memory": device_memory,
            "hardware_concurrency": hardware_concurrency,
            "platform": platform,
        }
        signature = generate_signature(user_data)

        # Check if user already exists
        if User.query.get(signature):
            return render_template("register.html", message="Browser already registered.")

        if User.query.get(username):
            return render_template("register.html", message='A user with this username already exist.')

        # Create new user
        new_user = User(
            signature=signature,
            username=username,
            language=language,
            color_depth=color_depth,
            screen_size=screen_size,
            device_memory=device_memory,
            hardware_concurrency=hardware_concurrency,
            platform=platform,
            active=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return render_template("register.html", message="Registration successful! Please contact admin to activate your account.")

    return render_template("register.html", message=None)

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admin = Admin.query.get(username)
        
        if not admin or not verify_password(admin.password_hash, password):
            return render_template("admin.html", message="Invalid credentials")

        session["admin_logged_in"] = True
        session["admin_username"] = username
        return redirect(url_for("admin_dashboard"))

    return render_template("admin.html", message=None)

@app.route("/admin/dashboard")
@require_admin
def admin_dashboard():
    users = User.query.all()
    users_list = []
    
    for user in users:
        users_list.append({
            "username": user.username,
            "signature": user.signature,
            "language": user.language,
            "color_depth": user.color_depth,
            "device_memory": user.device_memory,
            "hardware_concurrency": user.hardware_concurrency,
            "platform": user.platform,
            "screenSize": user.screen_size,
            "created": user.registered_at.isoformat(),
            "expires": user.expires.isoformat() if user.expires else None,
            "active": user.active,
        })
    
    return render_template("admin_dashboard.html", users=users_list)

@app.route("/admin/toggle/<signature>", methods=["POST"])
def admin_toggle_user(signature):
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user = User.query.get(signature)
    if not user:
        return jsonify({"success": False, "error": "User not found"})

    user.active = not user.active
    
    if user.active:
        user.expires = datetime.utcnow() + timedelta(days=365)
    else:
        user.expires = None
    
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/remove/<signature>", methods=["POST"])
def admin_remove_user(signature):
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user = User.query.get(signature)
    if not user:
        return jsonify({"success": False, "error": "User not found"})

    db.session.delete(user)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))



@app.route("/create-admin")
def create_admin():
    if not Admin.query.first():
        admin = Admin(
            username="admin",
            password_hash=hash_password("Barhatta&1984")
        )
        db.session.add(admin)
        db.session.commit()
        return "Default admin created (username: admin, password: Barhatta&1984)"
    return "Admin already exists"


@app.route('/verify', methods=['POST'])
def verify_user():
    user_data = request.json
    signature = generate_signature(user_data)

    user = User.query.get(signature)
    if not user:
        return jsonify({"status": "error", "message": "User not registered"}), 404

    if not user.active:
        return jsonify({"status": "error", "message": "User deactivated"}), 403

    if user.expires and user.expires < datetime.utcnow():
        return jsonify({"status": "error", "message": "User subscription expired"}), 403

    return jsonify({"status": "success", "message": "Access granted"})

if __name__ == "__main__":
    app.run(debug=True)