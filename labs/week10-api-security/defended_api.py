"""Student defense — Week 10 API Security, 6631503106.

Local teaching implementation; in-memory sessions and throttling are single-process.
Fixes the flaws in vulnerable_api.py.

Mitigations:
  API1:2023 BOLA   -> per-object ownership check (caller may only read their own
                      orders, unless admin).
  API3:2023 Mass Assignment -> explicit allow-list of bindable fields; server sets
                      sensitive fields (id, balance, is_admin) itself.
  API4:2023 Unrestricted Resource Consumption -> simple per-IP rate limiter on /api/login.

Run:  docker compose -f docker-compose.yml -f docker-compose.defended.yml up -d
"""
import time
import secrets
from threading import Lock
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096

USERS = {
    1: {"id": 1, "username": "alice", "password": "alice123",
        "balance": 100, "is_admin": False},
    2: {"id": 2, "username": "bob", "password": "bob123",
        "balance": 50, "is_admin": False},
    3: {"id": 3, "username": "carol", "password": "carol123",
        "balance": 9999, "is_admin": True},
}
ORDERS = {
    1: [{"order_id": "A-1", "item": "Keyboard", "total": 30}],
    2: [{"order_id": "B-1", "item": "Mouse", "total": 15}],
    3: [{"order_id": "C-1", "item": "Server rack", "total": 5000}],
}
_next_id = 4

# Only these keys may come from the client body. Everything else is ignored.
ALLOWED_CREATE_FIELDS = {"username", "password"}


# Hash the toy seed passwords too; never return hashes in API responses.
for _user in USERS.values():
    _user["password_hash"] = generate_password_hash(_user.pop("password"))
SESSIONS = {}
SESSION_TTL = 900
_state_lock = Lock()


def current_user():
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    with _state_lock:
        session = SESSIONS.get(token)
        if session is None:
            return None
        uid, expires = session
        if time.monotonic() >= expires:
            SESSIONS.pop(token, None)
            return None
    return USERS.get(uid)


def credentials():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None
    fields = {k: body[k] for k in ALLOWED_CREATE_FIELDS if k in body}
    if any(not isinstance(fields.get(k), str) or not fields[k].strip()
           for k in ALLOWED_CREATE_FIELDS):
        return None
    if len(fields["username"]) > 64 or len(fields["password"]) > 128:
        return None
    return fields


def public_user(user):
    return {k: user[k] for k in ("id", "username", "balance", "is_admin")}


# --- FIX API1: object-level authorization ------------------------------------
@app.get("/api/users/<int:uid>/orders")
def get_orders(uid):
    caller = current_user()
    if caller is None:
        return jsonify({"error": "authentication required"}), 401
    # The caller may only read their own orders unless they are an admin.
    if caller["id"] != uid and not caller["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(ORDERS.get(uid, []))


# --- FIX API3: allow-list binding --------------------------------------------
@app.post("/api/users")
def create_user():
    global _next_id
    fields = credentials()
    if fields is None:
        return jsonify({"error": "valid username and password required"}), 400
    password_hash = generate_password_hash(fields["password"])
    with _state_lock:
        if any(u["username"] == fields["username"] for u in USERS.values()):
            return jsonify({"error": "username already exists"}), 409
        user = {"id": _next_id, "username": fields["username"],
                "password_hash": password_hash, "balance": 0, "is_admin": False}
        USERS[_next_id] = user
        _next_id += 1
    return jsonify(public_user(user)), 201


# --- FIX API4: per-IP rate limiting ------------------------------------------
RATE_LIMIT = 5            # max attempts...
RATE_WINDOW = 60         # ...per this many seconds, per IP.
_attempts = defaultdict(list)


def rate_limited(ip):
    now = time.monotonic()
    with _state_lock:
        for key in list(_attempts):
            _attempts[key] = [t for t in _attempts[key] if now - t < RATE_WINDOW]
            if not _attempts[key]:
                del _attempts[key]
        if len(_attempts[ip]) >= RATE_LIMIT:
            return True
        _attempts[ip].append(now)
        return False


@app.post("/api/login")
def login():
    if rate_limited(request.remote_addr or "unknown"):
        return jsonify({"error": "too many requests"}), 429
    fields = credentials()
    if fields is None:
        return jsonify({"error": "valid username and password required"}), 400
    for u in list(USERS.values()):
        if u["username"] == fields["username"] and check_password_hash(
                u["password_hash"], fields["password"]):
            token = secrets.token_urlsafe(32)
            now = time.monotonic()
            with _state_lock:
                for old_token, (_, expires) in list(SESSIONS.items()):
                    if now >= expires:
                        del SESSIONS[old_token]
                SESSIONS[token] = (u["id"], now + SESSION_TTL)
            return jsonify({"ok": True, "access_token": token,
                            "token_type": "Bearer", "expires_in": SESSION_TTL})
    return jsonify({"ok": False}), 401


@app.get("/")
def index():
    return "Week 10 STUDENT DEFENDED API", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
