from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _extract_cvss(cvss_obj: Any) -> float | None:
    if not isinstance(cvss_obj, dict):
        return None
    best: float | None = None
    for entry in cvss_obj.values():
        if not isinstance(entry, dict):
            continue
        for key in ("V3Score", "V2Score", "Score"):
            val = entry.get(key)
            if isinstance(val, (int, float)):
                v = float(val)
                best = max(best, v) if best is not None else v
    return best


def parse_trivy(path: Path) -> dict[str, list[dict[str, Any]]]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {"vulnerabilities": [], "misconfigurations": [], "secrets": []}

    vulns: list[dict[str, Any]] = []
    misconfigs: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []

    for result in data.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        for v in result.get("Vulnerabilities", []) or []:
            if not isinstance(v, dict):
                continue
            vid = v.get("VulnerabilityID")
            fixed = v.get("FixedVersion")
            vulns.append(
                {
                    "scanner": "trivy",
                    "vulnerability_id": vid,
                    "cve_id": vid if isinstance(vid, str) and vid.upper().startswith("CVE-") else None,
                    "severity": v.get("Severity"),
                    "cvss_score": _extract_cvss(v.get("CVSS")),
                    "package_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": fixed,
                    "fix_available": bool(fixed),
                    "advisory_url": v.get("PrimaryURL"),
                    "description": v.get("Description") or v.get("Title"),
                }
            )
        for m in result.get("Misconfigurations", []) or []:
            if not isinstance(m, dict):
                continue
            misconfigs.append(
                {
                    "scanner": "trivy",
                    "file_path": target,
                    "rule_id": m.get("ID"),
                    "severity": m.get("Severity"),
                    "title": m.get("Title"),
                    "message": m.get("Message"),
                }
            )
        for s in result.get("Secrets", []) or []:
            if not isinstance(s, dict):
                continue
            secrets.append(
                {
                    "scanner": "trivy",
                    "file_path": target,
                    "secret_type": s.get("RuleID") or s.get("Category"),
                    "severity": s.get("Severity"),
                    "title": s.get("Title"),
                }
            )

    return {
        "vulnerabilities": vulns,
        "misconfigurations": misconfigs,
        "secrets": secrets,
    }
