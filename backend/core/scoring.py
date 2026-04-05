"""
Scoring Engine for SecureScan.

Takes the 10 OWASP test results and calculates:
  - Score: 0–100 (each test worth 10 points; deductions weighted by severity on fail)
  - Grade: A–F based on score ranges
  - Tests Passed: X / 10
"""

from typing import List, Dict, Any

# Severity-based deduction weights.
# If a test fails, we deduct points based on the worst severity in that test.
# Each test is worth 10 points max.
_SEVERITY_DEDUCTION = {
    "High": 10,    # Full 10-point deduction for a High-severity fail
    "Medium": 7,   # 7-point deduction for a Medium-severity fail
    "Low": 4,      # 4-point deduction for a Low-severity fail
}

# Grade boundaries
_GRADE_BOUNDARIES = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
]


def calculate_grade(score: int) -> str:
    """Convert a numeric score (0–100) to a letter grade (A–F)."""
    for threshold, grade in _GRADE_BOUNDARIES:
        if score >= threshold:
            return grade
    return "F"


def calculate_score(owasp_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate the overall security score from OWASP test results.

    Args:
        owasp_results: List of OWASP test result dicts, each containing
                       at minimum 'status' and 'severity' keys.

    Returns:
        Dict with 'score', 'grade', 'tests_passed', 'tests_total',
        and 'category_scores' (per-OWASP-category breakdown).
    """
    tests_total = len(owasp_results)
    tests_passed = 0
    total_score = 0
    category_scores = []

    for result in owasp_results:
        status = result.get("status", "fail")
        severity = result.get("severity", "Medium")
        owasp_id = result.get("owasp_id", "?")
        owasp_name = result.get("owasp_name", "Unknown")

        if status == "pass":
            points = 10
            tests_passed += 1
        else:
            deduction = _SEVERITY_DEDUCTION.get(severity, 7)
            points = max(0, 10 - deduction)

        total_score += points
        category_scores.append({
            "owasp_id": owasp_id,
            "owasp_name": owasp_name,
            "status": status,
            "points": points,
            "max_points": 10
        })

    # Normalize to 0–100 scale
    max_possible = tests_total * 10
    score = round((total_score / max_possible) * 100) if max_possible > 0 else 0
    grade = calculate_grade(score)

    return {
        "score": score,
        "grade": grade,
        "tests_passed": tests_passed,
        "tests_total": tests_total,
        "category_scores": category_scores
    }
