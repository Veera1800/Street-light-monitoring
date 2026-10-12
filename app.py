import datetime
import os
import sqlite3
from functools import wraps
from flask import Flask, jsonify, render_template, request, session
import jwt
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "wcj_secret_key_authenticator_2026"
JWT_SECRET = "wcj_jwt_secret_token_key"
DB_NAME = "users.db"


# Enable CORS manually for all responses
@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers[
        "Access-Control-Allow-Headers"
    ] = "Content-Type, Authorization"
    response.headers[
        "Access-Control-Allow-Methods"
    ] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# Database Initialization using Raw Cursors
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# JWT Authentication Decorator for Protected API Endpoints
def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Authorization token is missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = data["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# -----------------------------------------------------------------------------
# PAGE ROUTES (MVT - Template Renderers)
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# -----------------------------------------------------------------------------
# REST API ENDPOINTS
# -----------------------------------------------------------------------------


# API: Register User
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not username or not email or not password:
        return (
            jsonify({
                "message": (
                    "Missing fields. Username, email, and password required."
                )
            }),
            400,
        )

    hashed_pw = generate_password_hash(password)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_pw),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return (
            jsonify({"message": "Username or Email already exists."}),
            400,
        )


# API: Login User (Generates 1-Minute Expiry JWT)
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password FROM users WHERE username = ?",
        (username,),
    )
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        # Generate JWT Token valid for 1 minute (Auto-logout support)
        payload = {
            "user_id": user[0],
            "username": user[1],
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=1),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return (
            jsonify(
                {
                    "message": "Login successful",
                    "token": token,
                    "username": user[1],
                }
            ),
            200,
        )

    return jsonify({"message": "Invalid username or password"}), 401


# API: Forgot Password (Reset Password)
@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    new_password = data.get("new_password", "").strip()

    if not email or not new_password:
        return jsonify({"message": "Email and new password required"}), 400

    hashed_pw = generate_password_hash(new_password)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"message": "Email address not found"}), 404

    cursor.execute(
        "UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Password updated successfully!"}), 200


# API: Protected Home Route
@app.route("/api/home", methods=["GET"])
@token_required
def api_home(current_user):
    return (
        jsonify({
            "message": f"Welcome to WCJ Authenticator, {current_user}!",
            "status": "Authenticated",
        }),
        200,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)

