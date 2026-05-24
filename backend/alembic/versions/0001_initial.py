"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-23

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_value", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("ix_projects_target", "projects", ["target_type", "target_value"])

    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error_message", sa.Text()),
        sa.Column("risk_score", sa.Numeric(6, 2)),
        sa.Column("sbom_path", sa.Text()),
        sa.Column("grype_report_path", sa.Text()),
        sa.Column("trivy_report_path", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("ix_scans_project", "scans", ["project_id"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    op.create_table(
        "components",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text()),
        sa.Column("package_type", sa.Text()),
        sa.Column("purl", sa.Text()),
        sa.Column("license", sa.Text()),
        sa.Column("source_path", sa.Text()),
        sa.Column("direct", sa.Boolean()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("ix_components_scan", "components", ["scan_id"])
    op.create_index("ix_components_name", "components", ["name"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "component_id",
            UUID(as_uuid=True),
            sa.ForeignKey("components.id", ondelete="SET NULL"),
        ),
        sa.Column("scanner", sa.String(32), nullable=False),
        sa.Column("cve_id", sa.Text()),
        sa.Column("vulnerability_id", sa.Text()),
        sa.Column("severity", sa.String(32)),
        sa.Column("cvss_score", sa.Numeric(4, 1)),
        sa.Column("package_name", sa.Text()),
        sa.Column("installed_version", sa.Text()),
        sa.Column("fixed_version", sa.Text()),
        sa.Column(
            "fix_available", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("advisory_url", sa.Text()),
        sa.Column("description", sa.Text()),
        sa.Column("risk_score", sa.Numeric(6, 2)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("ix_vulnerabilities_scan", "vulnerabilities", ["scan_id"])
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_pkg", "vulnerabilities", ["package_name"])


def downgrade() -> None:
    op.drop_table("vulnerabilities")
    op.drop_table("components")
    op.drop_table("scans")
    op.drop_table("projects")
