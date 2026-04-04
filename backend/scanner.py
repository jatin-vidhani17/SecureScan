from typing import Dict, List

REQUIRED_SECURITY_HEADERS = {
    "Content-Security-Policy": "high",
    "Strict-Transport-Security": "medium",
    "X-Content-Type-Options": "medium",
    "X-Frame-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
}


def _severity_label(level: str) -> str:
    mapping = {"low": "Low", "medium": "Medium", "high": "High"}
    return mapping.get(level, "Low")


def scan_security_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    normalized = {k.lower(): v for k, v in headers.items()}

    for header, severity in REQUIRED_SECURITY_HEADERS.items():
        if header.lower() not in normalized:
            findings.append(
                {
                    "title": f"Missing {header}",
                    "severity": _severity_label(severity),
                    "description": f"The response does not include the {header} header.",
                    "remediation": f"Configure your server to send {header} with a secure policy.",
                    "evidence": "Header not found in HTTP response.",
                }
            )

    xcto = normalized.get("x-content-type-options", "")
    if xcto and xcto.lower() != "nosniff":
        findings.append(
            {
                "title": "Weak X-Content-Type-Options",
                "severity": "Medium",
                "description": "X-Content-Type-Options should be set to nosniff.",
                "remediation": "Set X-Content-Type-Options: nosniff.",
                "evidence": f"Current value: {xcto}",
            }
        )

    return findings
