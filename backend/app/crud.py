from __future__ import annotations

import uuid
from collections import Counter
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Component, Project, Scan, Vulnerability
from app.schemas import (
    ComponentOut,
    ScanDetail,
    ScanSummary,
    SeverityCounts,
    TopPackage,
    VulnerabilityOut,
)


def get_or_create_project(
    db: Session, *, name: str, target_type: str, target_value: str
) -> Project:
    existing = (
        db.query(Project)
        .filter(
            Project.name == name,
            Project.target_type == target_type,
            Project.target_value == target_value,
        )
        .first()
    )
    if existing:
        return existing
    project = Project(name=name, target_type=target_type, target_value=target_value)
    db.add(project)
    db.flush()
    return project


def create_scan(db: Session, project_id: uuid.UUID) -> Scan:
    scan = Scan(project_id=project_id, status="queued")
    db.add(scan)
    db.flush()
    return scan


def _severity_counts(db: Session, scan_id: uuid.UUID) -> SeverityCounts:
    rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id == scan_id)
        .group_by(Vulnerability.severity)
        .all()
    )
    counts = SeverityCounts()
    for sev, n in rows:
        s = (sev or "unknown").lower()
        if s in ("critical",):
            counts.critical += n
        elif s in ("high",):
            counts.high += n
        elif s in ("medium",):
            counts.medium += n
        elif s in ("low",):
            counts.low += n
        else:
            counts.unknown += n
    return counts


def _scan_to_summary(db: Session, scan: Scan) -> ScanSummary:
    component_count = (
        db.query(func.count(Component.id)).filter(Component.scan_id == scan.id).scalar() or 0
    )
    vulnerability_count = (
        db.query(func.count(Vulnerability.id)).filter(Vulnerability.scan_id == scan.id).scalar() or 0
    )
    fixable_count = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id == scan.id, Vulnerability.fix_available.is_(True))
        .scalar()
        or 0
    )
    severity = _severity_counts(db, scan.id)

    return ScanSummary(
        id=scan.id,
        project_id=scan.project_id,
        project_name=scan.project.name,
        target_type=scan.project.target_type,
        target_value=scan.project.target_value,
        status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error_message=scan.error_message,
        risk_score=float(scan.risk_score) if scan.risk_score is not None else None,
        created_at=scan.created_at,
        component_count=component_count,
        vulnerability_count=vulnerability_count,
        severity_counts=severity,
        fixable_count=fixable_count,
    )


def list_scans(db: Session, limit: int = 50) -> list[ScanSummary]:
    scans = (
        db.query(Scan)
        .join(Project)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_scan_to_summary(db, s) for s in scans]


def get_scan_detail(db: Session, scan_id: uuid.UUID) -> Optional[ScanDetail]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        return None
    summary = _scan_to_summary(db, scan)
    pkg_rows = (
        db.query(Vulnerability.package_name, func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id == scan_id, Vulnerability.package_name.isnot(None))
        .group_by(Vulnerability.package_name)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
        .all()
    )
    top = [TopPackage(package=p, count=n) for p, n in pkg_rows]
    return ScanDetail(
        **summary.model_dump(),
        top_packages=top,
        sbom_available=bool(scan.sbom_path),
        grype_available=bool(scan.grype_report_path),
        trivy_available=bool(scan.trivy_report_path),
    )


def list_components(
    db: Session,
    scan_id: uuid.UUID,
    *,
    search: Optional[str] = None,
    package_type: Optional[str] = None,
    vulnerable_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[ComponentOut]]:
    q = db.query(Component).filter(Component.scan_id == scan_id)
    if search:
        like = f"%{search.lower()}%"
        q = q.filter(func.lower(Component.name).like(like))
    if package_type:
        q = q.filter(Component.package_type == package_type)
    if vulnerable_only:
        vuln_subq = (
            select(Vulnerability.component_id)
            .where(Vulnerability.scan_id == scan_id, Vulnerability.component_id.isnot(None))
            .distinct()
        )
        q = q.filter(Component.id.in_(vuln_subq))
    total = q.count()
    items = q.order_by(Component.name).offset(offset).limit(limit).all()
    return total, [ComponentOut.model_validate(c) for c in items]


def list_vulnerabilities(
    db: Session,
    scan_id: uuid.UUID,
    *,
    severity: Optional[str] = None,
    fix_available: Optional[bool] = None,
    search: Optional[str] = None,
    scanner: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[VulnerabilityOut]]:
    q = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        q = q.filter(func.lower(Vulnerability.severity) == severity.lower())
    if fix_available is not None:
        q = q.filter(Vulnerability.fix_available.is_(fix_available))
    if scanner:
        q = q.filter(Vulnerability.scanner == scanner)
    if search:
        like = f"%{search.lower()}%"
        q = q.filter(
            func.lower(Vulnerability.package_name).like(like)
            | func.lower(Vulnerability.vulnerability_id).like(like)
            | func.lower(Vulnerability.cve_id).like(like)
        )
    total = q.count()
    items = (
        q.order_by(Vulnerability.risk_score.desc().nullslast(), Vulnerability.severity)
        .offset(offset)
        .limit(limit)
        .all()
    )
    return total, [VulnerabilityOut.model_validate(v) for v in items]


def dashboard_top_packages(
    db: Session, scan_id: uuid.UUID, n: int = 5
) -> list[TopPackage]:
    rows = (
        db.query(Vulnerability.package_name, func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id == scan_id, Vulnerability.package_name.isnot(None))
        .group_by(Vulnerability.package_name)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(n)
        .all()
    )
    return [TopPackage(package=p, count=c) for p, c in rows]
