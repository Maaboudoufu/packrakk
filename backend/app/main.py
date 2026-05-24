from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import health, reports, scans

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="PackRakk", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    return app


app = create_app()
