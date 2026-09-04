"""
Remediated sample for Week 2 scanning practice.
Planted flaws fixed: parameterized SQL, no shell=True, env vars for secrets, strong password hashing, debug=False.
"""
import os, sqlite3, subprocess
from flask import Flask, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# CWE-798: read secrets from environment variables instead of hardcoding
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: parameterized query with ? placeholder
    rows = con.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    con.close()
    return str(rows)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: pass arguments as list with shell=False
    return subprocess.check_output(["ping", "-c", "1", host], shell=False)

def store_password(pw):
    # CWE-327: strong salted hash (Werkzeug default: scrypt/pbkdf2)
    return generate_password_hash(pw)

if __name__ == "__main__":
    app.run(debug=False)  # CWE-489: debug mode disabled
