"""
BaseDetector — Abstract base class for all vulnerability detectors.
Provides standardized interface and result format.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Any


class BaseDetector(ABC):
    """Abstract base class for all vulnerability detectors."""

    def __init__(self, name: str, owasp_category: str):
        """
        Args:
            name: Human-readable detector name (e.g., "SQL Injection Detector")
            owasp_category: OWASP category (e.g., "A03")
        """
        self.name = name
        self.owasp_category = owasp_category
        self.context: Dict[str, Any] = {}

    def set_context(self, context: Dict[str, Any]) -> None:
        """Attach scan context (e.g., detected tech stack) for detector tuning."""
        self.context = context or {}

    @abstractmethod
    def scan_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Scan a single URL for vulnerabilities.
        
        Args:
            url: URL to scan
            
        Returns:
            Finding dict if vulnerability found, None otherwise.
            Finding dict should have: type, severity, description, evidence
        """
        pass

    def _make_finding(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: str,
        payload: Optional[str] = None,
        parameter: Optional[str] = None,
        url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build a standardized finding result.
        
        Args:
            vuln_type: Vulnerability type (e.g., "SQL Injection")
            severity: "Low", "Medium", or "High"
            description: Human-readable description
            evidence: What was detected (the evidence)
            payload: Optional payload used (if applicable)
            parameter: Optional parameter tested (if applicable)
            url: Optional URL where found
            
        Returns:
            Standardized finding dictionary
        """
        return {
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "payload": payload,
            "parameter": parameter,
            "url": url,
            "detector": self.name,
            "owasp_category": self.owasp_category
        }
