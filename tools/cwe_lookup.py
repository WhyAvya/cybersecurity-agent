CWE_DESCRIPTIONS = {
    "CWE-089": "SQL Injection — user input flows into SQL query without parameterization",
    "CWE-079": "Cross-site Scripting — user input rendered in HTML without escaping",
    "CWE-078": "OS Command Injection — user input passed to shell command",
    "CWE-022": "Path Traversal — user input used in file path construction",
    "CWE-190": "Integer Overflow — arithmetic operation wraps without bounds check",
}


def lookup_cwe(cwe_id: str) -> str:
    return CWE_DESCRIPTIONS.get(
        cwe_id.upper(),
        f"No description available for {cwe_id}"
    )