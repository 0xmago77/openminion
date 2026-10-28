"""Limits and immutable image identity for an offline Docker scanner."""

from pydantic import BaseModel, ConfigDict, Field


class DockerScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    daemon_socket: str = Field(pattern=r"^unix:///.+")
    worker_image: str = Field(pattern=r"^(?:[^\s]+@)?sha256:[0-9a-f]{64}$")
    memory_bytes: int = Field(default=1_073_741_824, ge=67_108_864)
    scratch_bytes: int = Field(default=536_870_912, ge=1_048_576)
    cpu_limit: float = Field(default=1.0, gt=0)
    pids_limit: int = Field(default=64, ge=16)
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=1_048_576)
    archive_bytes: int = Field(default=104_857_600, ge=1, le=104_857_600)
    source_entries: int = Field(default=10_000, ge=1, le=10_000)
