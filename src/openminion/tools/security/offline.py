"""Admit opaque archives and normalize evidence from the offline worker."""

from __future__ import annotations

from typing import Any, cast

import hashlib
import json
import re
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from openminion.modules.runtime.sandboxes.docker import DockerSandboxError
from .results import build_scan_result

from openminion.base.redaction import redact_mapping
from openminion.modules.runtime.sandboxes.docker_scan import DockerScanRunner
from openminion.modules.tool import preferred_artifact_ref
from openminion.modules.tool.errors import ToolRuntimeError

from .config import resolve_offline_scan_config
from .process import ScannerProcessResult
from .providers.semgrep import _parse_semgrep_result
from .providers.trivy import _parse_trivy_result
from .archive_schemas import (
    ArchiveScanArgs,
    SnapshotScanArgs,
    ScanTargetIdentity,
    ScanProvenance,
)
from .schemas import (
    ScanError,
    SecurityScanResult,
    SecurityConfigurationIdentity,
)


class WorkerResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scanner: str
    scanner_version: str = Field(min_length=1, max_length=120)
    scan_mode: str
    config_sha256: str
    database_sha256: str
    fixed_flags: list[str]
    return_code: int
    stdout: str
    stderr: str
    image_config: str = ""
    worker_id: str
    worker_image_digest: str
    cleanup_completed: bool


def scan_archive(args: ArchiveScanArgs, ctx: Any, *, check: str) -> dict[str, Any]:
    if ctx.permission_mode != "readonly" or not ctx.session_id:
        raise ToolRuntimeError(
            "POLICY_DENIED", "Offline scans require a readonly session"
        )
    config = resolve_offline_scan_config(ctx)
    target = config.targets.get(args.target_id)
    kind = "container_archive" if check == "image" else "source_snapshot"
    if target is None or target.kind != kind:
        raise ToolRuntimeError("POLICY_DENIED", "Unknown archive target or target kind")
    archive = Path(args.archive).expanduser().resolve(strict=True)
    root = target.root.expanduser().resolve(strict=True)
    if not archive.is_relative_to(root) or not archive.is_file():
        raise ToolRuntimeError("POLICY_DENIED", "Archive is outside its approved root")
    ctl = ctx.artifactctl
    limit = min(config.docker.archive_bytes, ctl.config.blob_store.max_ingest_bytes)
    if archive.stat().st_size > limit:
        raise ToolRuntimeError("INVALID_ARGUMENT", "Archive exceeds the ingest limit")
    with archive.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit or hashlib.sha256(data).hexdigest() != args.expected_sha256:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "Archive size or digest does not match"
        )
    raw = ctl.ingest_bytes(
        data, mime="application/x-tar", opaque=True, session_id=ctx.session_id
    )
    run_id = "security-scan:" + uuid4().hex
    ctl.ref_add("collection", run_id, raw.ref)
    started = time.monotonic()
    started_at = datetime.now(UTC).isoformat()
    try:
        with tempfile.TemporaryDirectory(prefix="openminion-scan-input-") as temporary:
            staged = Path(temporary) / "input.tar"
            staged.write_bytes(data)
            staged.chmod(0o444)
            result = DockerScanRunner(config.docker).run(
                input_path=staged,
                session_id=ctx.session_id,
                check=check,
                timeout=args.timeout_seconds,
                run_owner=run_id,
            )
        parsed = normalize_worker_result(result, args, check, started_at, started)
    except (DockerSandboxError, OSError, ValueError) as exc:
        parsed = failed_worker_result(
            exc, args, check, config.docker.worker_image, started_at, started
        )
    finally:
        ctl.ref_remove("collection", run_id, raw.ref)
    payload, _ = redact_mapping(parsed.model_dump(mode="json", exclude_none=True))
    ref = preferred_artifact_ref(
        ctx.write_artifact(
            f"security/scan-{uuid4().hex}.json",
            json.dumps(payload, sort_keys=True).encode(),
            "application/json",
            durable=True,
        )
    )
    parsed = SecurityScanResult.model_validate(payload)
    parsed.evidence_refs.append(ref)
    return parsed.as_tool_result()


def failed_worker_result(
    exc: Exception,
    args: ArchiveScanArgs,
    check: str,
    worker_image: str,
    started_at: str,
    started: float,
) -> SecurityScanResult:
    details = exc.details if isinstance(exc, DockerSandboxError) else {}
    parsed = build_scan_result(
        capability_id="security.scan_image"
        if check == "image"
        else "security.scan_snapshot",
        adapter_id="semgrep" if check == "code" else "trivy",
        target=args.target_id,
        started_at=started_at,
        started=started,
        status="timed_out" if details.get("timed_out") else "failed",
        error=ScanError(
            code=exc.code if isinstance(exc, DockerSandboxError) else "WORKER_FAILED",
            message="Offline scan did not complete; no absence claim is available.",
        ),
    )
    parsed.permission_mode = "readonly"
    parsed.target_identity = ScanTargetIdentity(
        kind="container_archive" if check == "image" else "source_snapshot",
        target_id=args.target_id,
        content_sha256=args.expected_sha256,
    )
    parsed.provenance = ScanProvenance(
        worker_id=str(details.get("worker_id", "")),
        worker_image_digest=worker_image,
        cleanup_completed=bool(details.get("cleanup_completed", False)),
    )
    return parsed


def normalize_worker_result(
    result: dict[str, Any], args: Any, check: str, started_at: str, started: float
) -> SecurityScanResult:
    result = WorkerResult.model_validate(result).model_dump()
    expected_scanner = "semgrep" if check == "code" else "trivy"
    expected_mode = {
        "code": "code",
        "dependencies": "vuln",
        "iac": "misconfig",
        "secrets": "secret",
        "image": "vuln",
    }[check]
    if result["scanner"] != expected_scanner or result["scan_mode"] != expected_mode:
        raise ValueError("Worker scanner identity does not match the requested check")
    configuration = SecurityConfigurationIdentity(
        scanner_version=result["scanner_version"],
        scan_mode=result["scan_mode"],
        config_sha256=result["config_sha256"],
        database_sha256=result["database_sha256"],
        fixed_flags=result["fixed_flags"],
    )
    process = ScannerProcessResult(
        return_code=result["return_code"],
        stdout=result["stdout"],
        stderr=result["stderr"],
    )
    common = dict(
        process=process,
        target=Path("/workspace/source"),
        target_name=args.target_id,
        max_findings=args.max_findings,
        scanner_version=result["scanner_version"],
        configuration_identity=configuration,
        started_at=started_at,
        started=started,
    )
    if check == "code":
        parsed = _parse_semgrep_result(**common)
    else:
        parsed = _parse_trivy_result(
            **common,
            capability_id="security.scan_image"
            if check == "image"
            else "security.scan_snapshot",
            scanner_kind=result["scan_mode"],
        )
    parsed.capability_id = (
        "security.scan_image" if check == "image" else "security.scan_snapshot"
    )
    parsed.permission_mode = "readonly"
    parsed.target_identity = ScanTargetIdentity(
        kind="container_archive" if check == "image" else "source_snapshot",
        target_id=args.target_id,
        content_sha256=args.expected_sha256,
    )
    parsed.provenance = ScanProvenance(
        worker_id=result["worker_id"],
        worker_image_digest=result["worker_image_digest"],
        cleanup_completed=result["cleanup_completed"],
    )
    return cast(SecurityScanResult, parsed)


def scan_snapshot_handler(args: Any, ctx: Any) -> dict[str, Any]:
    parsed = SnapshotScanArgs.model_validate(args)
    return scan_archive(parsed, ctx, check=parsed.check)


def scan_image_handler(args: Any, ctx: Any) -> dict[str, Any]:
    return scan_archive(ArchiveScanArgs.model_validate(args), ctx, check="image")


def recover_archive_scan(
    *, docker_config: Any, artifactctl: Any, worker_id: str, session_id: str
) -> dict[str, Any]:
    """Operator-only exact-ID recovery; never exposed as an agent tool."""
    recovered = DockerScanRunner(docker_config).recover(
        worker_id=worker_id, session_id=session_id
    )
    owner = recovered["run_owner"]
    if owner:
        if re.fullmatch(r"security-scan:[0-9a-f]{32}", owner) is None:
            raise ValueError("Recovery artifact owner is invalid")
        artifactctl.ref_remove_owner("collection", owner)
        staged = Path(recovered["input_path"])
        temporary_root = Path(tempfile.gettempdir()).resolve()
        if (
            staged.name != "input.tar"
            or not staged.parent.name.startswith("openminion-scan-input-")
            or staged.parent.parent.resolve() != temporary_root
        ):
            raise ValueError(
                "Recovery input path is outside the private staging directory"
            )
        staged.unlink()
        staged.parent.rmdir()
    return cast(dict[str, Any], recovered)
