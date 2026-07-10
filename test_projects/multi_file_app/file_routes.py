# test_projects/multi_file_app/file_routes.py

from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download_file():
    filename = request.args.get("file", "notes.txt")

    # Vulnerability 3: Path Traversal
    with open(filename, "r") as f:
        return f.read()