from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.scanner import check_tools
from app.schemas import HealthResponse, ToolStatus

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    db_ok = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:  # noqa: BLE001
        db_ok = f"error: {e.__class__.__name__}"

    tools = check_tools()
    return HealthResponse(
        status="ok",
        database=db_ok,
        tools=ToolStatus(**tools),
    )
