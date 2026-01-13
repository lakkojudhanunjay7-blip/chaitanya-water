import os
import random
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Optional: load .env in development
from dotenv import load_dotenv
load_dotenv()

# --- Config ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "data.db")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Secrets from env (NO defaults - must be provided via environment/.env)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")  # recommended to set in .env or host env

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
MANAGER_USERNAME = os.environ.get("MANAGER_USERNAME")
MANAGER_PASSWORD = os.environ.get("MANAGER_PASSWORD")

# Warn if secret key not set
if not app.secret_key:
    print("[WARN] FLASK_SECRET_KEY is not set. Set FLASK_SECRET_KEY env var in production.")

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin / manager

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_phone = db.Column(db.String(30), nullable=False)
    customer_address = db.Column(db.String(500), nullable=False)
    cans = db.Column(db.Integer, nullable=False, default=1)
    cooling = db.Column(db.Boolean, nullable=False, default=False)
    payment_method = db.Column(db.String(20), nullable=False)  # 'online' / 'offline'
    payment_status = db.Column(db.String(20), nullable=False, default="pending")  # pending/paid
    payment_details = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Helpers ---
def init_db_and_users():
    """
    Create tables and create admin/manager users if corresponding env vars are set.
    IMPORTANT: We do NOT create users when env vars are missing (keeps credentials out of code).
    To create admin/manager, set ADMIN_USERNAME, ADMIN_PASSWORD, MANAGER_USERNAME, MANAGER_PASSWORD in your environment/.env
    and then run init_db_and_users() via flask shell or let app call it on startup.
    """
    db.create_all()

    # Only create admin if both username & password env vars are provided
    if ADMIN_USERNAME and ADMIN_PASSWORD:
        admin = User.query.filter_by(username=ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                username=ADMIN_USERNAME,
                password_hash=generate_password_hash(ADMIN_PASSWORD),
                role="admin"
            )
            db.session.add(admin)

    # Only create manager if both username & password env vars are provided
    if MANAGER_USERNAME and MANAGER_PASSWORD:
        mgr = User.query.filter_by(username=MANAGER_USERNAME).first()
        if not mgr:
            mgr = User(
                username=MANAGER_USERNAME,
                password_hash=generate_password_hash(MANAGER_PASSWORD),
                role="manager"
            )
            db.session.add(mgr)

    db.session.commit()

# auth decorators
from functools import wraps
def require_customer(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "customer_phone" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapped

def require_staff(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "staff_id" not in session:
                return redirect(url_for("staff_login"))
            user = User.query.get(session["staff_id"])
            if not user:
                session.pop("staff_id", None)
                return redirect(url_for("staff_login"))
            if role and user.role != role:
                flash("Permission denied.", "error")
                return redirect(url_for("staff_dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# --- Routes ---
with app.app_context():
    init_db_and_users()

@app.route("/")
def index():
    """
    Homepage: UI unchanged. The form that previously POSTed to /send_otp still does so.
    Now /send_otp simply stores the phone in session and continues to the customer dashboard.
    """
    photos = [
        url_for("static", filename="images/plant1.jpg"),
        url_for("static", filename="images/plant2.jpg"),
    ]
    return render_template("index.html", photos=photos)

# Previously this sent OTP. Now it acts as "Continue" - logs the customer in directly.
@app.route("/send_otp", methods=["POST"])
def route_send_otp():
    phone = request.form.get("phone", "").strip()
    if not phone:
        flash("Enter phone number.", "error")
        return redirect(url_for("index"))

    # store phone in session (acts as login)
    session["customer_phone"] = phone
    flash("Continuing with phone number.", "info")
    return redirect(url_for("customer_dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/customer")
@require_customer
def customer_dashboard():
    phone = session["customer_phone"]
    orders = Order.query.filter_by(customer_phone=phone).order_by(Order.created_at.desc()).all()
    return render_template("customer_dashboard.html", phone=phone, orders=orders)

@app.route("/place_order", methods=["POST"])
@require_customer
def place_order():
    # Phone can be provided in the order form OR use logged-in phone
    phone_from_form = request.form.get("phone", "").strip()
    phone = phone_from_form or session.get("customer_phone")
    try:
        cans = int(request.form.get("cans", 1))
    except Exception:
        cans = 1
    cooling = request.form.get("cooling", "no") == "yes"
    address = request.form.get("address", "").strip()
    payment_method = request.form.get("payment_method", "offline")
    if not address or not phone:
        flash("Phone and Address are required.", "error")
        return redirect(url_for("customer_dashboard"))
    o = Order(
        customer_phone=phone,
        customer_address=address,
        cans=cans,
        cooling=cooling,
        payment_method=payment_method,
        payment_status="pending"
    )
    db.session.add(o)
    db.session.commit()
    flash("Order placed.", "success")
    return redirect(url_for("customer_dashboard"))

# staff login
@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["staff_id"] = user.id
            flash("Staff login OK.", "success")
            return redirect(url_for("staff_dashboard"))
        flash("Invalid staff credentials.", "error")
        return redirect(url_for("staff_login"))
    return render_template("staff_login.html")

@app.route("/staff/logout")
def staff_logout():
    session.pop("staff_id", None)
    flash("Staff logged out.", "info")
    return redirect(url_for("index"))

@app.route("/staff")
@require_staff()
def staff_dashboard():
    user = User.query.get(session["staff_id"])
    # show orders (customer phone will be visible in the table)
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("staff_dashboard.html", user=user, orders=orders)

@app.route("/staff/order/<int:order_id>/enter_payment", methods=["POST"])
@require_staff()
def enter_payment(order_id):
    user = User.query.get(session["staff_id"])
    order = Order.query.get_or_404(order_id)
    payment_details = request.form.get("payment_details", "").strip()
    if not payment_details:
        flash("Enter payment details.", "error")
        return redirect(url_for("staff_dashboard"))
    order.payment_details = f"{user.username}: {payment_details}"
    order.payment_status = "paid"
    db.session.commit()
    flash("Payment recorded.", "success")
    return redirect(url_for("staff_dashboard"))

@app.route("/staff/order/<int:order_id>/edit", methods=["GET", "POST"])
@require_staff(role="admin")
def edit_order(order_id):
    order = Order.query.get_or_404(order_id)
    if request.method == "POST":
        order.customer_address = request.form.get("customer_address", order.customer_address)
        try:
            order.cans = int(request.form.get("cans", order.cans))
        except Exception:
            pass
        order.cooling = request.form.get("cooling", "no") == "yes"
        order.payment_method = request.form.get("payment_method", order.payment_method)
        order.payment_status = request.form.get("payment_status", order.payment_status)
        order.payment_details = request.form.get("payment_details", order.payment_details)
        db.session.commit()
        flash("Order updated.", "success")
        return redirect(url_for("staff_dashboard"))
    return render_template("edit_order.html", order=order)

@app.route("/staff/order/<int:order_id>/delete", methods=["POST"])
@require_staff(role="admin")
def delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    flash("Order deleted.", "info")
    return redirect(url_for("staff_dashboard"))

@app.route("/order/<int:order_id>")
def view_order(order_id):
    order = Order.query.get_or_404(order_id)
    if "customer_phone" in session and session["customer_phone"] != order.customer_phone:
        return "Forbidden", 403
    return render_template("view_order.html", order=order)

# static files route (optional)
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# --- Run ---
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        open(DB_PATH, "a").close()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
