from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_value: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    risk_score: Mapped[Optional[float]] = mapped_column(Numeric(6, 2))
    sbom_path: Mapped[Optional[str]] = mapped_column(Text)
    grype_report_path: Mapped[Optional[str]] = mapped_column(Text)
    trivy_report_path: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="scans")
    components: Mapped[list["Component"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Component(Base):
    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(Text)
    package_type: Mapped[Optional[str]] = mapped_column(Text)
    purl: Mapped[Optional[str]] = mapped_column(Text)
    license: Mapped[Optional[str]] = mapped_column(Text)
    source_path: Mapped[Optional[str]] = mapped_column(Text)
    direct: Mapped[Optional[bool]] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="components")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    component_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("components.id", ondelete="SET NULL")
    )
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(Text)
    vulnerability_id: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(32))
    cvss_score: Mapped[Optional[float]] = mapped_column(Numeric(4, 1))
    package_name: Mapped[Optional[str]] = mapped_column(Text)
    installed_version: Mapped[Optional[str]] = mapped_column(Text)
    fixed_version: Mapped[Optional[str]] = mapped_column(Text)
    fix_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    advisory_url: Mapped[Optional[str]] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text)
    risk_score: Mapped[Optional[float]] = mapped_column(Numeric(6, 2))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")
