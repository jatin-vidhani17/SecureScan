import json
import os
from datetime import datetime
from typing import List, Dict, Any

class ReportGenerator:
    def __init__(self, target: str, vulnerabilities: List[Dict[str, Any]]):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now().isoformat()

    def generate_json(self) -> str:
        report = {
            "target": self.target,
            "scanned_at": self.timestamp,
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "total": len(self.vulnerabilities),
                "high": sum(1 for v in self.vulnerabilities if v.get("severity") == "High"),
                "medium": sum(1 for v in self.vulnerabilities if v.get("severity") == "Medium"),
                "low": sum(1 for v in self.vulnerabilities if v.get("severity") == "Low"),
            }
        }
        return json.dumps(report, indent=2)

    def generate_text(self) -> str:
        lines = [
            f"=== SecureScan Report ===",
            f"Target: {self.target}",
            f"Date: {self.timestamp}",
            f"Total Vulnerabilities: {len(self.vulnerabilities)}",
            "========================="
        ]
        
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            lines.append(f"\n[{idx}] {vuln.get('type')} ({vuln.get('severity')})")
            lines.append(f"    URL: {vuln.get('url')}")
            if vuln.get('parameter'):
                lines.append(f"    Parameter: {vuln.get('parameter')}")
            if vuln.get('payload'):
                lines.append(f"    Payload: {vuln.get('payload')}")
            if vuln.get('details'):
                lines.append(f"    Details: {vuln.get('details')}")

        return "\n".join(lines)
