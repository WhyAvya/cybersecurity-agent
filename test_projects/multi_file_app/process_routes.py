# test_projects/multi_file_app/process_routes.py

import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_process():
    command = request.args.get("cmd", "whoami")

    # Vulnerability 4: Command Injection through subprocess
    subprocess.call(command, shell=True)

    return "process executed"