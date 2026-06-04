import os
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def get_db():
    """
    Creates an in-memory SQLite database with a sample users table.
    Resets on every request — keeps the sandbox stateless and clean.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
    conn.commit()
    return conn


# VULNERABLE_CODE_PLACEHOLDER


@app.route("/test", methods=["POST"])
def test():
    """
    Accepts login attempt via POST.
    Returns 200 + welcome message if login succeeds, 401 if it fails.
    Attack success is determined by checking if this endpoint returns 200.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    result = login(username, password)
    if result:
        return jsonify({"status": "success", "message": "Welcome admin"}), 200
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)