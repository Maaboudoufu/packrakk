from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _extract_license(licenses: Any) -> str | None:
    if not licenses:
        return None
    names: list[str] = []
    if isinstance(licenses, list):
        for entry in licenses:
            if isinstance(entry, dict):
                lic = entry.get("license") or {}
                if isinstance(lic, dict):
                    name = lic.get("id") or lic.get("name")
                    if name:
                        names.append(str(name))
                expr = entry.get("expression")
                if expr:
                    names.append(str(expr))
            elif isinstance(entry, str):
                names.append(entry)
    return ", ".join(names) if names else None


def parse_cyclonedx(path: Path) -> list[dict[str, Any]]:
    """Parse a CycloneDX SBOM JSON file produced by Syft."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    components: list[dict[str, Any]] = []
    for c in data.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        if not name:
            continue
        components.append(
            {
                "name": str(name),
                "version": c.get("version"),
                "package_type": c.get("type"),
                "purl": c.get("purl"),
                "license": _extract_license(c.get("licenses")),
                "source_path": None,
                "direct": None,
            }
        )
    return components
