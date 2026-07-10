# test_projects/multi_file_app/app.py

from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # Vulnerability 1: OS Command Injection
    os.system("ping " + host)

    return "ping complete"