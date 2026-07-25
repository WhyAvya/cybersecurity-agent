import os
from flask import request


def run_report():
    name = request.args.get("name")
    command = build_report_command(name)
    os.system(command)
