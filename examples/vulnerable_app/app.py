import os
from flask import Flask, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return os.system("ping -n 1 " + host)
