# test_projects/single_file_test/vulnerable_single.py

import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    # Vulnerability 1: OS Command Injection
    os.system("ping " + host)

    return "ping executed"


@app.route("/lookup")
def lookup_user():
    user_id = request.args.get("id", "1")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnerability 2: SQL Injection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    return str(cursor.fetchall())


@app.route("/read")
def read_file():
    filename = request.args.get("file", "notes.txt")

    # Vulnerability 3: Path Traversal
    with open(filename, "r") as f:
        return f.read()


@app.route("/run")
def run_command():
    command = request.args.get("cmd", "whoami")

    # Vulnerability 4: Command Injection using subprocess
    subprocess.call(command, shell=True)

    return "command executed"