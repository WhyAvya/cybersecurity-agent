from flask import request


def search_users(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
