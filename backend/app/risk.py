from __future__ import annotations

from typing import Iterable, Optional

CRITICAL_PACKAGES = {
    "openssl",
    "glibc",
    "curl",
    "nginx",
    "apache",
    "node",
    "python",
    "java",
    "spring",
    "express",
    "lodash",
    "requests",
    "urllib3",
    "log4j",
}

SEVERITY_BASE = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
    "unknown": 10,
    "negligible": 10,
}


def normalize_severity(severity: Optional[str]) -> str:
    if not severity:
        return "unknown"
    s = severity.lower()
    if s in SEVERITY_BASE:
        return s
    return "unknown"


def vulnerability_risk(
    *,
    severity: Optional[str],
    fix_available: bool,
    package_name: Optional[str],
    cvss_score: Optional[float],
) -> float:
    base = SEVERITY_BASE[normalize_severity(severity)]
    score = float(base)
    if fix_available:
        score += 5
    if package_name and package_name.lower() in CRITICAL_PACKAGES:
        score += 5
    if cvss_score is not None and cvss_score >= 9.0:
        score += 5
    return min(score, 100.0)


def scan_risk(vuln_scores: Iterable[float]) -> Optional[float]:
    scores = sorted((s for s in vuln_scores if s is not None), reverse=True)
    if not scores:
        return None
    top = scores[:10]
    avg = sum(top) / len(top)
    return round(max(avg, scores[0]), 2)


def risk_label(score: Optional[float]) -> str:
    if score is None:
        return "n/a"
    if score >= 90:
        return "Urgent"
    if score >= 70:
        return "High priority"
    if score >= 45:
        return "Medium priority"
    if score >= 20:
        return "Low priority"
    return "Informational"
