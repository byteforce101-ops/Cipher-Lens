"""
Scoring engine for aggregating security findings into numerical scores and letter grades.
"""

from typing import Any, Dict, List, Tuple


def calculate_score(findings: List[Dict[str, str]]) -> Tuple[int, str, Dict[str, int]]:
    """
    Computes:
    - Numerical security score (0 - 100)
    - Letter grade ("Grade A", "Grade B", "Grade C", "Grade D", "Grade F")
    - Severity counts breakdown dictionary: {"Critical": c, "High": h, "Medium": m, "Low": l}
    """
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    base_score = 100

    # Severity penalties
    penalties = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
    }

    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
            base_score -= penalties.get(sev, 5)

    score = max(0, min(100, base_score))

    if score >= 90:
        grade = "Grade A"
    elif score >= 80:
        grade = "Grade B"
    elif score >= 65:
        grade = "Grade C"
    elif score >= 50:
        grade = "Grade D"
    else:
        grade = "Grade F"

    return score, grade, counts
