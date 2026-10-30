from datetime import datetime, time, timedelta
from functools import wraps
import os, random, secrets, json, math
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Ensure the instance directory path is absolute
instance_path = os.path.join(app.root_path, "instance")
os.makedirs(instance_path, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(instance_path, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ----------------------------- Database Models -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="student")
    department = db.Column(db.String(80), default="General")
    clearance = db.Column(db.Integer, default=1)  # 1=Public, 2=Restricted, 3=Confidential
    active = db.Column(db.Boolean, default=True)
    trusted_device = db.Column(db.String(100), default="browser-default")
    failed_logins = db.Column(db.Integer, default=0)
    home_lat = db.Column(db.Float, nullable=True)
    home_lon = db.Column(db.Float, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    author = db.Column(db.String(120), default="Unknown")
    category = db.Column(db.String(80), default="General")
    department = db.Column(db.String(80), default="General")
    classification = db.Column(db.String(30), default="Public")
    required_clearance = db.Column(db.Integer, default=1)
    description = db.Column(db.Text, default="")
    critical = db.Column(db.Boolean, default=False)
    resource_type = db.Column(db.String(30), default="book")
    uploader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    file_name = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    resource_id = db.Column(db.Integer, db.ForeignKey("resource.id"), nullable=True)
    action = db.Column(db.String(30), nullable=False)
    abac_result = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    risk_tier = db.Column(db.String(20), default="Low")
    decision = db.Column(db.String(30), nullable=False)
    reason = db.Column(db.String(255), default="")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    signals_json = db.Column(db.Text, default="{}")
    device_label = db.Column(db.String(160), default="Unknown browser")
    location_label = db.Column(db.String(160), default="Not shared")
    user = db.relationship("User")
    resource = db.relationship("Resource")


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------------------- Security Engines -----------------------------
# Research Paper Table II: Risk indicators & weights
DEFAULT_RISK_WEIGHTS = {
    "unfamiliar_device": 25,
    "unfamiliar_location": 20,
    "failed_logins": 35,
    "unusual_access_time": 10,
    "sensitive_action": 10,
    "new_browser": 25,
    "rapid_requests": 15
}


def get_current_weights():
    return session.get("custom_risk_weights", DEFAULT_RISK_WEIGHTS)


def evaluate_abac(user, resource, action):
    """
    Policy Decision Point (PDP): Mandatory ABAC Evaluation (Section V-B).
    """
    if not user or not user.active:
        return False, "Account is inactive or disabled."

    if action not in {"view", "download", "modify", "delete"}:
        return False, "Unsupported action requested."

    if user.role == "admin":
        return True, "Admin access authorized under security management policy."

    if user.role == "student":
        if action not in {"view", "download"}:
            return False, "Students can only view and download library resources."
    elif user.role == "faculty":
        if action not in {"view", "download", "modify"}:
            return False, "Faculty action not permitted."
    elif user.role == "librarian":
        if action not in {"view", "download", "modify", "delete"}:
            return False, "Action not permitted for librarian role."
    else:
        return False, "Unknown user role."

    if resource.resource_type == "student_submission" and resource.uploader_id != user.id and user.role not in {"faculty", "librarian"}:
        return False, "Student submission is not accessible to this account."

    if user.clearance < resource.required_clearance:
        return False, f"Insufficient clearance level (Required: {resource.required_clearance}, Yours: {user.clearance})."

    if resource.department not in {"General", user.department} and user.role not in {"librarian", "admin"}:
        return False, "Resource belongs to another department."

    if action == "download" and resource.classification == "Confidential" and user.clearance < 3:
        return False, "Confidential resources cannot be downloaded without Level 3 clearance."

    return True, "Role, department, clearance, and requested action satisfy policy."


def haversine_km(lat1, lon1, lat2, lon2):
    try:
        radius = 6371.0
        p1, p2 = math.radians(lat1), math.radians(lat2)
        dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
        a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        return 2 * radius * math.asin(math.sqrt(a))
    except (TypeError, ValueError):
        return None


def calculate_risk(user, action, device_id, location=None, simulation=None):
    """
    Dynamic Risk Assessment Engine (Algorithm 1 & Section V-C).
    """
    now = datetime.utcnow()
    weights = get_current_weights()

    recent_failures = LoginAttempt.query.filter_by(email=user.email, success=False)\
        .filter(LoginAttempt.timestamp >= now - timedelta(minutes=15)).count()
    recent_requests = AccessLog.query.filter_by(user_id=user.id)\
        .filter(AccessLog.timestamp >= now - timedelta(minutes=2)).count()

    known_device = bool(user.trusted_device and device_id and device_id == user.trusted_device)

    location = location or {}
    lat, lon = location.get("lat"), location.get("lon")
    location_known = user.home_lat is not None and user.home_lon is not None and lat is not None and lon is not None
    distance = haversine_km(user.home_lat, user.home_lon, lat, lon) if location_known else None

    sim = simulation or {}
    
    unfamiliar_device = bool(sim.get("unfamiliar_device", sim.get("new_browser", not known_device)))
    unfamiliar_location = bool(sim.get("unfamiliar_location", location_known and distance > 50))
    failed_logins = bool(sim.get("failed_logins", recent_failures >= 3))
    unusual_access_time = bool(sim.get("unusual_access_time", now.hour < 6 or now.hour >= 22))
    sensitive_action = bool(sim.get("sensitive_action", action in {"download", "modify", "delete"}))
    rapid_requests = bool(sim.get("rapid_requests", recent_requests >= 8))

    signals = {
        "unfamiliar_device": unfamiliar_device,
        "new_browser": unfamiliar_device,
        "unfamiliar_location": unfamiliar_location,
        "failed_logins": failed_logins,
        "unusual_access_time": unusual_access_time,
        "sensitive_action": sensitive_action,
        "rapid_requests": rapid_requests
    }

    score_components = [
        weights.get("unfamiliar_device", 25) if unfamiliar_device else 0,
        weights.get("unfamiliar_location", 20) if unfamiliar_location else 0,
        weights.get("failed_logins", 35) if failed_logins else 0,
        weights.get("unusual_access_time", 10) if unusual_access_time else 0,
        weights.get("sensitive_action", 10) if sensitive_action else 0,
    ]
    if rapid_requests and "rapid_requests" in weights:
        score_components.append(weights["rapid_requests"])

    score = min(100, sum(score_components))

    if score < 30:
        tier = "Low"
    elif score < 60:
        tier = "Medium"
    else:
        tier = "High"

    return score, tier, signals, distance


def decide_access(user, resource, action, device_id, location=None, simulation=None):
    """
    Policy-First Decision Flow (Figure 2 / Table III).
    """
    allowed, reason = evaluate_abac(user, resource, action)
    if not allowed:
        return {
            "abac": "Fail", "score": 0, "tier": "Not evaluated",
            "decision": "Deny", "reason": reason, "signals": {}, "distance_km": None
        }

    score, tier, signals, distance = calculate_risk(user, action, device_id, location=location, simulation=simulation)

    if tier == "Low":
        decision, reason = "Allow", "ABAC passed and contextual risk is low."
    elif tier == "Medium":
        decision, reason = "Challenge_MFA", "ABAC passed; step-up verification is required."
    elif resource.critical:
        decision, reason = "Deny", "High risk detected for a critical resource."
    else:
        decision, reason = "Restrict", "High risk detected; access is limited to read-only."

    return {
        "abac": "Pass", "score": score, "tier": tier,
        "decision": decision, "reason": reason, "signals": signals, "distance_km": distance
    }


def log_access(user, resource, action, result, device_label="Unknown browser", location_label="Not shared"):
    entry = AccessLog(
        user_id=user.id if user else None,
        resource_id=resource.id if resource else None,
        action=action,
        abac_result=result["abac"],
        risk_score=result["score"],
        risk_tier=result["tier"],
        decision=result["decision"],
        reason=result["reason"],
        signals_json=json.dumps(result.get("signals", {})),
        device_label=device_label,
        location_label=location_label,
    )
    db.session.add(entry)
    db.session.commit()


def notify(user_id, title, message):
    db.session.add(Notification(user_id=user_id, title=title, message=message))
    db.session.commit()


# ----------------------------- Helpers & Routes -----------------------------
def current_user():
    return db.session.get(User, session.get("user_id")) if session.get("user_id") else None


@app.template_filter("fromjson")
def fromjson_filter(value):
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


@app.context_processor
def inject_user():
    user = current_user()
    unread = Notification.query.filter_by(user_id=user.id, is_read=False).count() if user else 0
    return {"current_user": user, "unread_notifications": unread}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        department = request.form.get("department", "General")

        if not name or not email or len(password) < 8:
            flash("Enter all details. Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
            return redirect(url_for("register"))

        user = User(name=name, email=email, role="student", department=department, clearance=1, trusted_device="browser-default")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        success = bool(user and user.check_password(password) and user.active)
        db.session.add(LoginAttempt(email=email, success=success))

        if not success:
            if user:
                user.failed_logins += 1
            db.session.commit()
            recent = LoginAttempt.query.filter_by(email=email, success=False)\
                .filter(LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=15)).count()
            flash(f"Login failed. {recent} failed attempt(s) recorded in the last 15 minutes.", "error")
            return redirect(url_for("login"))

        user.failed_logins = 0
        device_token = request.cookies.get("device_id") or secrets.token_urlsafe(24)
        if user.trusted_device in (None, "", "browser-default"):
            user.trusted_device = device_token

        db.session.commit()
        session["user_id"] = user.id
        session["device_id"] = device_token

        response = redirect(url_for("dashboard"))
        response.set_cookie("device_id", device_token, httponly=True, samesite="Lax")
        flash(f"Welcome back, {user.name.split()[0]}!", "success")
        return response
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user.role == "admin":
        return redirect(url_for("audit"))

    resources = Resource.query.order_by(Resource.created_at.desc()).all()
    unread_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
    logs = AccessLog.query.filter_by(user_id=user.id).order_by(AccessLog.timestamp.desc()).limit(8).all()
    stats = {
        "resources": Resource.query.count(),
        "users": User.query.count() if user.role == "admin" else None,
        "requests": AccessLog.query.filter_by(user_id=user.id).count(),
        "denied": AccessLog.query.filter_by(user_id=user.id, decision="Deny").count(),
    }
    return render_template("dashboard.html", resources=resources, logs=logs, stats=stats, unread_count=unread_count)


@app.route("/catalogue")
@login_required
def catalogue():
    if current_user().role == "admin":
        return redirect(url_for("audit"))
    q = request.args.get("q", "").strip()
    query = Resource.query
    if q:
        query = query.filter(Resource.title.ilike(f"%{q}%") | Resource.author.ilike(f"%{q}%") | Resource.category.ilike(f"%{q}%"))
    return render_template("catalogue.html", resources=query.order_by(Resource.title).all(), q=q)


@app.route("/resource/<int:resource_id>/<action>", methods=["GET", "POST"])
@login_required
def access_resource(resource_id, action):
    if action not in {"view", "download", "modify", "delete"}:
        abort(404)

    user = current_user()
    resource = db.session.get(Resource, resource_id) or abort(404)
    device_id = session.get("device_id", "browser-default")

    try:
        lat = float(request.args.get("lat")) if request.args.get("lat") else None
        lon = float(request.args.get("lon")) if request.args.get("lon") else None
    except (ValueError, TypeError):
        lat, lon = None, None

    location = {"lat": lat, "lon": lon}

    if lat is not None and lon is not None:
        if user.home_lat is not None and user.home_lon is not None:
            km = haversine_km(user.home_lat, user.home_lon, lat, lon)
            location_label = f"Coarse Signal ({'Familiar' if km <= 50 else 'Unfamiliar'} · {km:.1f} km)"
        else:
            location_label = "Coarse Signal (Shared)"
    else:
        location_label = "Location Context (Not shared)"

    device_platform = request.user_agent.platform or "Unknown platform"
    device_label = f"{device_platform} · {'Recognized Browser' if device_id == user.trusted_device else 'Unfamiliar Browser'}"

    result = decide_access(user, resource, action, device_id, location)

    if result["decision"] == "Challenge_MFA":
        otp = f"{secrets.randbelow(900000) + 100000:06d}"
        session["pending_access"] = {
            "resource_id": resource.id, "action": action,
            "score": result["score"], "tier": result["tier"],
            "reason": result["reason"], "device_label": device_label, "location_label": location_label
        }
        session["demo_otp"] = otp
        return render_template("mfa.html", resource=resource, action=action, result=result, otp=otp)

    log_access(user, resource, action, result, device_label, location_label)

    if result["decision"] in {"Deny", "Restrict"}:
        notify(user.id, "Access Notice", f"Your request to {action} '{resource.title}' resulted in decision: {result['decision']}.")

    return render_template("access_result.html", resource=resource, action=action, result=result)


@app.route("/verify-mfa", methods=["POST"])
@login_required
def verify_mfa():
    pending = session.get("pending_access")
    otp = request.form.get("otp", "").strip()

    if not pending:
        return redirect(url_for("catalogue"))

    user = current_user()
    resource = db.session.get(Resource, pending["resource_id"])

    valid_otp = session.get("demo_otp")
    if valid_otp and otp == valid_otp and resource:
        result = {
            "abac": "Pass", "score": pending["score"], "tier": pending["tier"],
            "decision": "Allow", "reason": "Step-up MFA verification succeeded.", "signals": {}
        }
    else:
        result = {
            "abac": "Pass", "score": pending["score"], "tier": pending["tier"],
            "decision": "Deny", "reason": "Step-up MFA verification failed.", "signals": {}
        }

    log_access(user, resource, pending["action"], result, pending.get("device_label", "Unknown browser"), pending.get("location_label", "Not shared"))

    if result["decision"] == "Deny":
        notify(user.id, "MFA Verification Failed", f"Step-up verification failed for '{resource.title}'. Access denied.")

    session.pop("pending_access", None)
    session.pop("demo_otp", None)
    return render_template("access_result.html", resource=resource, action=pending["action"], result=result)


@app.route("/manage-resources", methods=["GET", "POST"])
@login_required
@role_required("librarian", "faculty", "admin")
def manage_resources():
    user = current_user()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Resource title is required.", "error")
            return redirect(url_for("manage_resources"))

        if user.role == "faculty":
            resource_type = "course_material"
            classification = "Restricted"
            clearance = 1
            department = user.department
            critical = False
        else:
            resource_type = "book"
            classification = request.form.get("classification", "Public")
            clearance = int(request.form.get("required_clearance", 1))
            department = request.form.get("department", "General")
            critical = request.form.get("critical") == "on"

        uploaded = request.files.get("resource_file")
        saved_name = ""
        if uploaded and uploaded.filename:
            safe = secure_filename(uploaded.filename)
            ext = safe.rsplit(".", 1)[-1].lower() if "." in safe else ""
            if ext not in {"pdf", "doc", "docx", "ppt", "pptx", "txt"}:
                flash("Upload PDF, DOC, DOCX, PPT, PPTX or TXT files only.", "error")
                return redirect(url_for("manage_resources"))
            os.makedirs(os.path.join(app.root_path, "uploads"), exist_ok=True)
            saved_name = f"{secrets.token_hex(8)}_{safe}"
            uploaded.save(os.path.join(app.root_path, "uploads", saved_name))

        resource = Resource(
            title=title, author=request.form.get("author", user.name),
            category=request.form.get("category", "Course Material" if user.role == "faculty" else "General"),
            department=department, classification=classification, required_clearance=clearance,
            description=request.form.get("description", ""), critical=critical,
            resource_type=resource_type, uploader_id=user.id, file_name=saved_name
        )
        db.session.add(resource)
        db.session.commit()
        flash("Resource successfully added to catalogue.", "success")
        return redirect(url_for("manage_resources"))

    if user.role == "faculty":
        resources = Resource.query.filter_by(uploader_id=user.id).order_by(Resource.id.desc()).all()
    else:
        resources = Resource.query.order_by(Resource.id.desc()).all()

    return render_template("manage_resources.html", resources=resources)


@app.route("/resource-file/<int:resource_id>")
@login_required
def download_upload(resource_id):
    from flask import send_from_directory

    user = current_user()
    resource = db.session.get(Resource, resource_id) or abort(404)

    if not resource.file_name:
        abort(404)

    try:
        lat = float(request.args.get("lat")) if request.args.get("lat") else None
        lon = float(request.args.get("lon")) if request.args.get("lon") else None
    except (ValueError, TypeError):
        lat, lon = None, None

    location = {"lat": lat, "lon": lon}
    device_id = session.get("device_id", "")
    platform = request.user_agent.platform or "Unknown platform"

    device_label = f"{platform} · {'Recognized Browser' if device_id == user.trusted_device else 'Unfamiliar Browser'}"
    location_label = "Location Context (Shared)" if lat is not None else "Location Context (Not shared)"

    result = decide_access(user, resource, "download", device_id, location)
    log_access(user, resource, "download", result, device_label, location_label)

    if result["decision"] == "Allow":
        return send_from_directory(os.path.join(app.root_path, "uploads"), resource.file_name, as_attachment=True)

    notify(user.id, "Download Restricted", f"Download request for '{resource.title}' was denied/restricted.")
    flash("File download was not approved based on current access policy.", "error")
    return redirect(url_for("catalogue"))


@app.route("/notifications")
@login_required
def notifications():
    user = current_user()
    items = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    for item in items:
        item.is_read = True
    db.session.commit()
    return render_template("notifications.html", notifications=items)


@app.route("/profile/location", methods=["POST"])
@login_required
def save_home_location():
    user = current_user()
    try:
        user.home_lat = float(request.form["lat"])
        user.home_lon = float(request.form["lon"])
        db.session.commit()
        flash("Usual location saved for contextual risk evaluation.", "success")
    except (KeyError, ValueError):
        flash("Location update failed. Provide valid numeric coordinates.", "error")
    return redirect(url_for("dashboard"))


@app.route("/admin/risk-settings", methods=["GET", "POST"])
@login_required
@role_required("admin")
def risk_settings():
    if request.method == "POST":
        current_w = dict(get_current_weights())
        for key in DEFAULT_RISK_WEIGHTS:
            try:
                if key in request.form:
                    current_w[key] = max(0, min(100, int(request.form.get(key, current_w[key]))))
            except ValueError:
                pass
        session["custom_risk_weights"] = current_w
        flash("Session risk weights updated.", "success")
        return redirect(url_for("risk_settings"))
    return render_template("risk_settings.html", weights=get_current_weights())


@app.route("/admin/users")
@login_required
@role_required("admin")
def manage_users():
    return render_template("manage_users.html", users=User.query.order_by(User.id).all())


@app.route("/admin/user/<int:user_id>/update", methods=["POST"])
@login_required
@role_required("admin")
def update_user(user_id):
    user = db.session.get(User, user_id) or abort(404)
    requested_role = request.form.get("role", user.role)

    if requested_role != "admin" or user.email == "admin@library.demo":
        user.role = requested_role

    user.department = request.form.get("department", user.department)
    user.clearance = int(request.form.get("clearance", user.clearance))
    user.active = request.form.get("active") == "on"
    db.session.commit()
    flash("User access permissions updated.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/audit")
@login_required
@role_required("admin")
def audit():
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(200).all()
    return render_template("audit.html", logs=logs)


@app.route("/simulate")
@login_required
@role_required("admin")
def simulate():
    resources = Resource.query.order_by(Resource.title).all()
    return render_template("simulate.html", resources=resources)


@app.route("/api/simulate", methods=["POST"])
@login_required
@role_required("admin")
def api_simulate():
    data = request.get_json(force=True)
    resource = db.session.get(Resource, int(data.get("resource_id", 0)))
    target = User.query.filter_by(role=data.get("role", "student")).first()

    if not resource or not target:
        return jsonify({"error": "Select a valid role and resource."}), 404

    action = data.get("action", "view")
    simulation = {
        key: bool(data.get(key, False))
        for key in ("unfamiliar_device", "new_browser", "unfamiliar_location", "failed_logins", "unusual_access_time", "sensitive_action", "rapid_requests")
    }

    result = decide_access(target, resource, action, "simulated-device", simulation=simulation)
    log_access(target, resource, action, result, "Admin Simulation Engine", "Simulated Context")
    return jsonify(result)


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="Access Denied: Insufficient permissions."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="Requested resource or page not found."), 404


def seed_data():
    if User.query.count() == 0:
        demo_users = [
            ("Admin User", "admin@library.demo", "Admin123!", "admin", "General", 3),
            ("Librarian User", "librarian@library.demo", "Lib12345!", "librarian", "General", 3),
            ("Aarav Student", "student@library.demo", "Student123!", "student", "Computer Science", 1),
            ("Diya Faculty", "faculty@library.demo", "Faculty123!", "faculty", "Computer Science", 2),
        ]
        for name, email, password, role, dept, clearance in demo_users:
            u = User(name=name, email=email, role=role, department=dept, clearance=clearance)
            u.set_password(password)
            db.session.add(u)

    if Resource.query.count() == 0:
        samples = [
            Resource(title="Python Programming Fundamentals", author="A. Sharma", category="Programming", department="General", classification="Public", required_clearance=1, description="Beginner-friendly guide to Python."),
            Resource(title="Database Management Systems", author="R. Elmasri", category="Database", department="Computer Science", classification="Public", required_clearance=1, description="Relational databases and SQL."),
            Resource(title="Secure Systems Architecture", author="Cybersecurity Lab", category="Cybersecurity", department="Computer Science", classification="Confidential", required_clearance=3, description="Sensitive security research.", critical=True),
        ]
        db.session.add_all(samples)
    db.session.commit()


# Startup initialization & safe migration
with app.app_context():
    db.create_all()
    try:
        inspector = inspect(db.engine)
        user_cols = {c["name"] for c in inspector.get_columns("user")}
        for name, sql_type in (("home_lat", "FLOAT"), ("home_lon", "FLOAT")):
            if name not in user_cols:
                db.session.execute(text(f"ALTER TABLE user ADD COLUMN {name} {sql_type}"))

        log_cols = {c["name"] for c in inspector.get_columns("access_log")}
        for name, sql_type, default in (
            ("signals_json", "TEXT", "'{}'"),
            ("device_label", "VARCHAR(160)", "'Unknown browser'"),
            ("location_label", "VARCHAR(160)", "'Not shared'"),
        ):
            if name not in log_cols:
                db.session.execute(text(f"ALTER TABLE access_log ADD COLUMN {name} {sql_type} DEFAULT {default}"))

        db.session.commit()
    except Exception:
        db.session.rollback()

    seed_data()

if __name__ == "__main__":
    app.run(debug=True)