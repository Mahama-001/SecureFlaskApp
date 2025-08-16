import os
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
from flask_talisman import Talisman
csrf = CSRFProtect(app)
import bleach

email=bleach.clean(request.form['email'])
password=bleach.clean(request.form['password'])

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme-secret")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # True in production behind HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SQLALCHEMY_DATABASE_URI="sqlite:///sensi.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login_page"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri=os.environ.get("LIMITER_STORAGE_URI", "memory://"),
)

CORS(app)

# --- CSP: allow inline styles + FontAwesome from cdnjs + data: fonts/images
csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'"],
    "style-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    "font-src": ["'self'", "https://cdnjs.cloudflare.com", "data:"],
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
}
Talisman(app, content_security_policy=csp)

# ---------------------------------------------------------------------------
# Database model
# ---------------------------------------------------------------------------
class UserModel(db.Model, UserMixin):
    __tablename__ = 'users'
    email = db.Column(db.String(120), primary_key=True, unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phonenumber = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return self.email  # Use email as the unique identifier for Flask-Login


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_email):
    return UserModel.query.get(user_email)


@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

def sanitize_basic(text: str) -> str:
    return (text or "").strip()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register_page():
    if request.method == "POST":
        first_name = sanitize_basic(request.form.get("first_name"))
        last_name = sanitize_basic(request.form.get("last_name"))
        phonenumber = sanitize_basic(request.form.get("phonenumber"))
        email = sanitize_basic(request.form.get("email")).lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([first_name, last_name, phonenumber, email, password, confirm_password]):
            flash("❌ All fields are required.", "error")
            return redirect(url_for("register_page"))

        if password != confirm_password:
            flash("❌ Passwords do not match!", "error")
            return redirect(url_for("register_page"))

        if UserModel.query.filter_by(email=email).first():
            flash("❌ Email already exists. Please log in.", "error")
            return redirect(url_for("login_page"))

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = UserModel(
            email=email, first_name=first_name, last_name=last_name,
            phonenumber=phonenumber, password=password_hash
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("❌ Error creating account. Try again.", "error")
            return redirect(url_for("register_page"))

        flash("✅ Registration successful! Please log in.", "success")
        return redirect(url_for("login_page"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login_page():
    if request.method == "POST":
        email = sanitize_basic(request.form.get("email")).lower()
        password = request.form.get("password", "")

        user = UserModel.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session.permanent = True
            flash("✅ Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("❌ Invalid email or password!", "error")
        return redirect(url_for("login_page"))

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("✅ You have been logged out.", "success")
    return redirect(url_for("login_page"))

@app.route("/healthz")
@limiter.exempt
def healthz():
    return {"status": "ok"}, 200

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
