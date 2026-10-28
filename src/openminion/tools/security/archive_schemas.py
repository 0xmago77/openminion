"""Offline archive request and provenance contracts."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class ScanTargetIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["source_snapshot", "container_archive", "source"]
    target_id: str = Field(min_length=1, max_length=200)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ScanProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker_id: str
    worker_image_digest: str
    isolation_mode: Literal["offline_docker"] = "offline_docker"
    cleanup_completed: bool


class ArchiveScanArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=200)
    archive: str = Field(min_length=1)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    timeout_seconds: float = Field(default=120, gt=0, le=600)
    max_findings: int = Field(default=100, ge=1, le=500)


class SnapshotScanArgs(ArchiveScanArgs):
    check: Literal["code", "dependencies", "iac", "secrets"]
