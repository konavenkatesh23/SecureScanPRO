from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from database import get_db_connection

bcrypt = Bcrypt()

auth_bp = Blueprint("auth", __name__)

# ==========================
# HOME
# ==========================

@auth_bp.route("/")
def home():
    return render_template("login.html")


# ==========================
# LOGIN
# ==========================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    email = request.form["email"]
    password = request.form["password"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE email=%s",
        (email,)
    )

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user and bcrypt.check_password_hash(user["password"], password):

        session["user_id"] = user["user_id"]
        session["username"] = user["username"]

        flash("Login Successful!", "success")

        return redirect(url_for("dashboard.dashboard"))

    flash("Invalid Email or Password!", "danger")

    return redirect(url_for("auth.login"))


# ==========================
# REGISTER
# ==========================

@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE email=%s",
        (email,)
    )

    existing_user = cursor.fetchone()

    if existing_user:

        flash("Email already exists!", "warning")

        cursor.close()
        conn.close()

        return redirect(url_for("auth.register"))

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    cursor.execute(
        """
        INSERT INTO users
        (
            username,
            email,
            password
        )
        VALUES
        (
            %s,%s,%s
        )
        """,
        (
            username,
            email,
            hashed_password
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration Successful!", "success")

    return redirect(url_for("auth.login"))


# ==========================
# LOGOUT
# ==========================

@auth_bp.route("/logout")
def logout():

    session.clear()

    flash("Logged out successfully.", "success")

    return redirect(url_for("auth.login"))