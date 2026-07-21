def greet(name: str) -> str:
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in {" ", "-", "_"})
    return f"Hello, {cleaned or 'guest'}"


if __name__ == "__main__":
    print(greet("developer"))
