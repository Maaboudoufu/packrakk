from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import crud
from app.database import get_db
from app.scanner import execute_scan, validate_image_ref
from app.schemas import (
    PaginatedComponents,
    PaginatedVulnerabilities,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetail,
    ScanSummary,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=202)
def create_scan(
    payload: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    if payload.target_type != "docker_image":
        raise HTTPException(status_code=400, detail="Only docker_image is supported in MVP")
    if not validate_image_ref(payload.target_value):
        raise HTTPException(status_code=400, detail="Invalid docker image reference")

    project = crud.get_or_create_project(
        db,
        name=payload.name,
        target_type=payload.target_type,
        target_value=payload.target_value,
    )
    scan = crud.create_scan(db, project.id)
    db.commit()

    background_tasks.add_task(execute_scan, scan.id, payload.target_value)

    return ScanCreateResponse(scan_id=scan.id, project_id=project.id, status=scan.status)


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200)) -> list[ScanSummary]:
    return crud.list_scans(db, limit=limit)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> ScanDetail:
    detail = crud.get_scan_detail(db, scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return detail


@router.get("/{scan_id}/components", response_model=PaginatedComponents)
def get_components(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    search: Optional[str] = None,
    package_type: Optional[str] = None,
    vulnerable_only: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> PaginatedComponents:
    total, items = crud.list_components(
        db,
        scan_id,
        search=search,
        package_type=package_type,
        vulnerable_only=vulnerable_only,
        limit=limit,
        offset=offset,
    )
    return PaginatedComponents(total=total, items=items)


@router.get("/{scan_id}/vulnerabilities", response_model=PaginatedVulnerabilities)
def get_vulnerabilities(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    fix_available: Optional[bool] = None,
    search: Optional[str] = None,
    scanner: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> PaginatedVulnerabilities:
    total, items = crud.list_vulnerabilities(
        db,
        scan_id,
        severity=severity,
        fix_available=fix_available,
        search=search,
        scanner=scanner,
        limit=limit,
        offset=offset,
    )
    return PaginatedVulnerabilities(total=total, items=items)
