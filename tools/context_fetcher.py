def fetch_context(file_path: str, line: int, window: int = 10):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        start = max(0, line - window - 1)
        end = min(len(lines), line + window)

        numbered = [
            f"{i + start + 1}: {lines[i + start]}"
            for i in range(end - start)
        ]

        return "".join(numbered)

    except Exception as e:
        return f"ERROR: {str(e)}"