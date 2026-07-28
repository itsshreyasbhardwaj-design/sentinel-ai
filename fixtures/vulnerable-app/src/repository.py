"""Intentionally insecure data access fixture for Sentinel AI's test suite. Do not deploy."""

import hashlib
import os

import requests
from flask import Flask, request, send_file

app = Flask(__name__)


def find_user(cursor, user_id):
    # SQL injection through f-string interpolation.
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def search_orders(cursor, term):
    # SQL injection through percent formatting of the query itself.
    cursor.execute("SELECT * FROM orders WHERE name LIKE '%s'" % term)
    return cursor.fetchall()


def fetch_profile(url):
    # TLS verification disabled.
    return requests.get(url, verify=False)


def hash_password(password):
    # Broken hash algorithm for password storage.
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/download")
def download():
    # Path traversal from request input.
    return send_file(os.path.join("/var/data", request.args.get("name")))


def check_access(user):
    # Security check implemented with assert, removed under python -O.
    assert user.is_admin, "admin permission required"


if __name__ == "__main__":
    # Debug mode exposes the Werkzeug interactive console.
    app.run(debug=True, host="0.0.0.0")
