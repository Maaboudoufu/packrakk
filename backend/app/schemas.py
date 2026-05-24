from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ToolStatus(BaseModel):
    syft: bool
    grype: bool
    trivy: bool


class HealthResponse(BaseModel):
    status: str
    database: str
    tools: ToolStatus


class ScanCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_type: str = Field(default="docker_image")
    target_value: str = Field(min_length=1, max_length=500)


class ScanCreateResponse(BaseModel):
    scan_id: uuid.UUID
    project_id: uuid.UUID
    status: str


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class TopPackage(BaseModel):
    package: str
    count: int


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    target_type: str
    target_value: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    risk_score: Optional[float] = None
    created_at: datetime
    component_count: int = 0
    vulnerability_count: int = 0
    severity_counts: SeverityCounts = SeverityCounts()
    fixable_count: int = 0


class ScanDetail(ScanSummary):
    top_packages: list[TopPackage] = []
    sbom_available: bool = False
    grype_available: bool = False
    trivy_available: bool = False


class ComponentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: Optional[str] = None
    package_type: Optional[str] = None
    purl: Optional[str] = None
    license: Optional[str] = None
    source_path: Optional[str] = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scanner: str
    cve_id: Optional[str] = None
    vulnerability_id: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    fix_available: bool = False
    advisory_url: Optional[str] = None
    description: Optional[str] = None
    risk_score: Optional[float] = None


class PaginatedComponents(BaseModel):
    total: int
    items: list[ComponentOut]


class PaginatedVulnerabilities(BaseModel):
    total: int
    items: list[VulnerabilityOut]
