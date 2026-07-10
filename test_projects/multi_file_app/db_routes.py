# test_projects/multi_file_app/db_routes.py

import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    username = request.args.get("name", "guest")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnerability 2: SQL Injection
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)

    return str(cursor.fetchall())