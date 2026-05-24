from __future__ import annotations

import logging
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import Component, Scan, Vulnerability
from app.parsers.grype_parser import parse_grype
from app.parsers.syft_parser import parse_cyclonedx
from app.parsers.trivy_parser import parse_trivy
from app.risk import scan_risk, vulnerability_risk

log = logging.getLogger(__name__)

TOOLS = ("syft", "grype", "trivy")

# Allow standard docker image refs: registry/path:tag, digests, dots, dashes, underscores
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@\-]{0,254}$")


def check_tools() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in TOOLS}


def validate_image_ref(image: str) -> bool:
    if not image or len(image) > 255:
        return False
    return bool(_IMAGE_RE.match(image))


def _run(cmd: list[str], *, timeout: int, out_path: Optional[Path] = None) -> tuple[int, str, str]:
    """Run a subprocess safely (no shell). Returns (returncode, stdout, stderr)."""
    log.info("running: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if out_path is not None:
        out_path.write_text(proc.stdout)
    return proc.returncode, proc.stdout, proc.stderr


def execute_scan(scan_id: uuid.UUID, image: str) -> None:
    """Run syft, grype, trivy for a scan, parse output, persist results."""
    settings = get_settings()
    scan_dir = settings.scans_storage_dir / str(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)

    sbom_path = scan_dir / "sbom.json"
    grype_path = scan_dir / "grype.json"
    trivy_path = scan_dir / "trivy.json"

    db: Session = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.warning("scan %s missing", scan_id)
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        timeout = settings.scanner_timeout_seconds
        tools = check_tools()
        errors: list[str] = []

        # Syft -> SBOM
        if tools["syft"]:
            try:
                rc, _, stderr = _run(
                    ["syft", image, "-o", "cyclonedx-json"],
                    timeout=timeout,
                    out_path=sbom_path,
                )
                if rc != 0:
                    errors.append(f"syft exit {rc}: {stderr.strip()[:500]}")
                else:
                    scan.sbom_path = str(sbom_path)
            except Exception as e:
                errors.append(f"syft failed: {e}")
        else:
            errors.append("syft not installed")

        # Grype -> vulnerabilities from SBOM (fallback to image if no sbom)
        if tools["grype"]:
            try:
                if sbom_path.exists() and sbom_path.stat().st_size > 0:
                    grype_target = f"sbom:{sbom_path}"
                else:
                    grype_target = image
                rc, _, stderr = _run(
                    ["grype", grype_target, "-o", "json"],
                    timeout=timeout,
                    out_path=grype_path,
                )
                if rc != 0:
                    errors.append(f"grype exit {rc}: {stderr.strip()[:500]}")
                else:
                    scan.grype_report_path = str(grype_path)
            except Exception as e:
                errors.append(f"grype failed: {e}")
        else:
            errors.append("grype not installed")

        # Trivy -> vulnerabilities from image
        if tools["trivy"]:
            try:
                rc, _, stderr = _run(
                    [
                        "trivy",
                        "image",
                        "--quiet",
                        "--format",
                        "json",
                        "--output",
                        str(trivy_path),
                        image,
                    ],
                    timeout=timeout,
                )
                if rc != 0:
                    errors.append(f"trivy exit {rc}: {stderr.strip()[:500]}")
                else:
                    scan.trivy_report_path = str(trivy_path)
            except Exception as e:
                errors.append(f"trivy failed: {e}")
        else:
            errors.append("trivy not installed")

        # Parse SBOM
        component_lookup: dict[tuple[str, Optional[str]], uuid.UUID] = {}
        if scan.sbom_path:
            for c in parse_cyclonedx(sbom_path):
                comp = Component(scan_id=scan.id, **c)
                db.add(comp)
                db.flush()
                key = (comp.name.lower(), (comp.version or "").lower() or None)
                component_lookup.setdefault(key, comp.id)

        # Parse Grype
        if scan.grype_report_path:
            for v in parse_grype(grype_path):
                _persist_vuln(db, scan.id, v, component_lookup)

        # Parse Trivy
        if scan.trivy_report_path:
            trivy_data = parse_trivy(trivy_path)
            for v in trivy_data["vulnerabilities"]:
                _persist_vuln(db, scan.id, v, component_lookup)

        db.flush()

        # Compute scan-level risk score
        vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan.id)
            .all()
        )
        if vulns:
            scan.risk_score = scan_risk([float(v.risk_score) for v in vulns if v.risk_score is not None])

        # If any scanner produced data, treat as completed even with warnings.
        produced_data = any(
            [scan.sbom_path, scan.grype_report_path, scan.trivy_report_path]
        )
        if produced_data:
            scan.status = "completed"
            if errors:
                scan.error_message = "; ".join(errors)[:2000]
        else:
            scan.status = "failed"
            scan.error_message = "; ".join(errors)[:2000] or "No scanner produced output"

        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:  # noqa: BLE001
        log.exception("scan %s crashed", scan_id)
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error_message = f"unexpected error: {e}"[:2000]
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _persist_vuln(
    db: Session,
    scan_id: uuid.UUID,
    v: dict,
    component_lookup: dict[tuple[str, Optional[str]], uuid.UUID],
) -> None:
    component_id = None
    pkg = (v.get("package_name") or "").lower()
    ver = (v.get("installed_version") or "").lower() or None
    if pkg:
        component_id = component_lookup.get((pkg, ver)) or component_lookup.get((pkg, None))

    risk = vulnerability_risk(
        severity=v.get("severity"),
        fix_available=bool(v.get("fix_available")),
        package_name=v.get("package_name"),
        cvss_score=v.get("cvss_score"),
    )
    db.add(
        Vulnerability(
            scan_id=scan_id,
            component_id=component_id,
            scanner=v["scanner"],
            vulnerability_id=v.get("vulnerability_id"),
            cve_id=v.get("cve_id"),
            severity=v.get("severity"),
            cvss_score=v.get("cvss_score"),
            package_name=v.get("package_name"),
            installed_version=v.get("installed_version"),
            fixed_version=v.get("fixed_version"),
            fix_available=bool(v.get("fix_available")),
            advisory_url=v.get("advisory_url"),
            description=v.get("description"),
            risk_score=risk,
        )
    )
