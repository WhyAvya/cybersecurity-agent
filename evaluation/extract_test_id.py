import os
import re


def extract_test_id(file_path: str):

    filename = os.path.basename(file_path)

    match = re.search(
        r"(BenchmarkTest\d+)",
        filename
    )

    if match:
        return match.group(1)

    return None


if __name__ == "__main__":

    tests = [
        "data/BenchmarkPython/testcode/BenchmarkTest00001.py",
        "data/BenchmarkPython/testcode/BenchmarkTest00123.py",
        "data/BenchmarkPython/testcode/BenchmarkTest01234.py"
    ]

    for test in tests:

        print(test)

        print(
            "→",
            extract_test_id(test)
        )

        print()