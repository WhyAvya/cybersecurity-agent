# test_projects/vulnerable_app/app.py

import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    os.system("ping -c 1 " + host)
    return "done"


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    return str(cursor.fetchall())


@app.route("/read")
def read_file():
    filename = request.args.get("file", "notes.txt")

    with open(filename, "r") as f:
        return f.read()