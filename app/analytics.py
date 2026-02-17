from collections import Counter


def build_analytics(reports: list[dict]) -> dict:
    total = len(reports)
    severity_counter = Counter([r.get("severity", "Unknown") for r in reports])
    vuln_counter = Counter([
        r.get("extracted_fields", {}).get("vulnerability_type", "unknown")
        for r in reports
    ])

    critical_reports = [r for r in reports if r.get("severity") == "Critical"]

    return {
        "total_reports": total,
        "severity_distribution": dict(severity_counter),
        "common_attack_types": dict(vuln_counter.most_common(10)),
        "critical_vulnerabilities": critical_reports[:20],
    }
