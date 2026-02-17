REMEDIATION_MAP = {
    "sql injection": [
        "Use parameterized queries and ORM-safe query builders.",
        "Apply input validation and output encoding.",
        "Restrict DB account permissions to least privilege.",
    ],
    "xss": [
        "Apply contextual output encoding for HTML/JS contexts.",
        "Enable Content Security Policy and sanitize user inputs.",
        "Use secure templating defaults in frontend rendering.",
    ],
    "idor": [
        "Enforce server-side object-level authorization checks.",
        "Use indirect object references and scoped access controls.",
        "Log and alert on suspicious sequential object access.",
    ],
    "rce": [
        "Remove unsafe command execution paths.",
        "Apply strict allowlists and sandbox execution contexts.",
        "Patch vulnerable dependencies and isolate runtime privileges.",
    ],
}


def suggest_remediation(vulnerability_type: str) -> list[str]:
    return REMEDIATION_MAP.get(
        vulnerability_type,
        [
            "Validate and sanitize all untrusted inputs.",
            "Apply least privilege and harden authentication controls.",
            "Add monitoring, alerting, and abuse detection coverage.",
        ],
    )
