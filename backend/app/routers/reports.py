from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan

router = APIRouter(prefix="/scans/{scan_id}/reports", tags=["reports"])


def _serve(path_str: str | None, filename: str) -> FileResponse:
    if not path_str:
        raise HTTPException(status_code=404, detail="Report not available")
    path = Path(path_str)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing on disk")
    return FileResponse(path, media_type="application/json", filename=filename)


@router.get("/sbom")
def download_sbom(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> FileResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serve(scan.sbom_path, f"sbom-{scan_id}.json")


@router.get("/grype")
def download_grype(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> FileResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serve(scan.grype_report_path, f"grype-{scan_id}.json")


@router.get("/trivy")
def download_trivy(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> FileResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serve(scan.trivy_report_path, f"trivy-{scan_id}.json")
