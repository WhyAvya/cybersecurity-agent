import subprocess
from flask import request


def run_report():
    command = request.args.get("command")
    command = "status"
    subprocess.run(["git", command], shell=False)
