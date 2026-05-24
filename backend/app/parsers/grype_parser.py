from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _extract_cvss(cvss_list: Any) -> float | None:
    if not isinstance(cvss_list, list):
        return None
    best: float | None = None
    for entry in cvss_list:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics") or {}
        score = metrics.get("baseScore") if isinstance(metrics, dict) else None
        if score is None:
            score = entry.get("base_score") or entry.get("baseScore")
        if isinstance(score, (int, float)):
            best = max(best, float(score)) if best is not None else float(score)
    return best


def parse_grype(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    out: list[dict[str, Any]] = []
    for match in data.get("matches", []) or []:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        if not isinstance(vuln, dict) or not isinstance(artifact, dict):
            continue

        fix = vuln.get("fix") or {}
        fix_versions: list[str] = []
        if isinstance(fix, dict):
            raw = fix.get("versions") or []
            if isinstance(raw, list):
                fix_versions = [str(v) for v in raw if v]
        fix_available = bool(fix_versions)
        fixed_version = fix_versions[0] if fix_versions else None

        urls = vuln.get("urls") or []
        advisory_url = None
        if isinstance(urls, list) and urls:
            advisory_url = str(urls[0])
        if not advisory_url:
            advisory_url = vuln.get("dataSource")

        vid = vuln.get("id")
        cve_id = str(vid) if isinstance(vid, str) and vid.upper().startswith("CVE-") else None

        out.append(
            {
                "scanner": "grype",
                "vulnerability_id": str(vid) if vid else None,
                "cve_id": cve_id,
                "severity": vuln.get("severity"),
                "cvss_score": _extract_cvss(vuln.get("cvss")),
                "package_name": artifact.get("name"),
                "installed_version": artifact.get("version"),
                "fixed_version": fixed_version,
                "fix_available": fix_available,
                "advisory_url": advisory_url,
                "description": vuln.get("description"),
            }
        )
    return out
