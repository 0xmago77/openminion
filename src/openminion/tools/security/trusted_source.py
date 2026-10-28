"""Run scheduled trusted Git snapshots with the pinned offline scanner assets."""

from __future__ import annotations

from typing import Any

import hashlib
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from openminion.modules.runtime.sandboxes.docker_scan import DockerScanRunner
from openminion.modules.tool.errors import ToolRuntimeError

from .archive_schemas import ArchiveScanArgs
from .config import resolve_offline_scan_config
from .offline import normalize_worker_result, failed_worker_result
from .schemas import SecurityScanResult
from openminion.modules.runtime.sandboxes.docker import DockerSandboxError
from .schedule import clean_revision, configured_admission, admission_fingerprint


def run_context(ctx: Any) -> dict[str, Any]:
    metadata = ctx.policy.raw.get("context_metadata", {})
    raw = metadata.get("security_scan_context")
    if not raw:
        return {}
    import json

    result: dict[str, Any] = json.loads(raw)
    return result


def scheduled_scan(
    args: Any, *, ctx: Any, target: Any, config: Any, check: str
) -> SecurityScanResult | None:
    context = run_context(ctx)
    admission = configured_admission(agent_id=ctx.agent_id, ctx=ctx)
    if admission is None:
        if context:
            raise ToolRuntimeError(
                "POLICY_DENIED", "Scheduled scan admission was revoked"
            )
        return None
    if context.get("admission_fingerprint") != admission_fingerprint(admission):
        raise ToolRuntimeError(
            "POLICY_DENIED", "Scheduled scan admission changed during execution"
        )
    revision = context.get("revision")
    if (
        ctx.permission_mode != "readonly"
        or target.resolve() != admission.root.resolve()
        or check not in admission.checks
        or args.expected_target_revision != revision
        or not args.include_evidence_artifact
        or not revision
        or clean_revision(target) != revision
        or admission.expires_at <= datetime.now(UTC)
    ):
        raise ToolRuntimeError(
            "POLICY_DENIED", "Scheduled scan is outside its admitted scope"
        )
    docker = resolve_offline_scan_config(ctx).docker
    started = time.monotonic()
    started_at = datetime.now(UTC).isoformat()
    with tempfile.TemporaryDirectory(prefix="openminion-trusted-scan-") as temporary:
        archive = Path(temporary) / "source.tar"
        with archive.open("wb") as stream:
            subprocess.run(
                ("git", "-C", str(target), "archive", "--format=tar", revision),  # noqa: S603,S607
                stdout=stream,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=10,
            )
        if archive.stat().st_size > docker.archive_bytes:
            raise ToolRuntimeError(
                "INVALID_ARGUMENT", "Trusted source archive exceeds its limit"
            )
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.chmod(0o444)
        request = ArchiveScanArgs(
            target_id=str(admission.root),
            archive=str(archive),
            expected_sha256=digest,
            max_findings=args.max_findings,
        )
        try:
            result = DockerScanRunner(docker).run(
                input_path=archive,
                session_id=ctx.session_id,
                check=check,
                timeout=min(args.timeout_seconds, admission.timeout_seconds),
            )
            parsed = normalize_worker_result(
                result, request, check, started_at, started
            )
        except (DockerSandboxError, OSError, ValueError) as exc:
            parsed = failed_worker_result(
                exc, request, check, docker.worker_image, started_at, started
            )
    parsed.capability_id = {
        "code": "security.scan_code",
        "dependencies": "security.scan_dependencies",
        "iac": "security.scan_artifact",
        "secrets": "security.scan_secrets",
    }[check]
    parsed.target = "."
    parsed.target_revision = revision
    assert parsed.target_identity is not None
    parsed.target_identity.kind = "source"
    try:
        unchanged = clean_revision(target) == revision
    except ToolRuntimeError:
        unchanged = False
    if not unchanged and parsed.ok:
        parsed.status = "partial"
        parsed.partial_reason = "source_revision_changed"
    return parsed


def admit_scheduled_report(args: Any, ctx: Any) -> None:
    admission = configured_admission(agent_id=ctx.agent_id, ctx=ctx)
    context = run_context(ctx)
    if context and admission is None:
        raise ToolRuntimeError(
            "POLICY_DENIED", "Scheduled report admission was revoked"
        )
    if admission is not None:
        if context.get("admission_fingerprint") != admission_fingerprint(admission):
            raise ToolRuntimeError(
                "POLICY_DENIED", "Scheduled report admission changed"
            )
        revision = context.get("revision")
        if args.scope.target_revision != revision or set(
            args.scope.requested_checks
        ) != set(admission.checks):
            raise ToolRuntimeError(
                "POLICY_DENIED", "Scheduled report differs from admitted source scope"
            )
