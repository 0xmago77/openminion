"""Artifact integrity report assembly."""

from __future__ import annotations

import hashlib
from pathlib import Path

from openminion.modules.artifact.models import (
    ArtifactMeta,
    VerifyIssue,
    VerifyReport,
)
from openminion.modules.artifact.storage.fs_cas import FileSystemCASBlobStore


def hash_file(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def read_file_sample(path: Path, size: int = 4096) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def build_verify_report(
    rows: list[ArtifactMeta],
    *,
    blob_store: FileSystemCASBlobStore,
    orphan_shas: list[str],
) -> VerifyReport:
    issues: list[VerifyIssue] = []

    for row in rows:
        if not blob_store.exists(row.sha256):
            issues.append(VerifyIssue(sha256=row.sha256, issue="missing_blob"))
            continue

        with Path(blob_store.path_for(row.sha256)).open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != row.sha256:
            issues.append(
                VerifyIssue(
                    sha256=row.sha256,
                    issue="digest_mismatch",
                    expected_sha256=row.sha256,
                    actual_sha256=actual,
                )
            )

    issues.extend(
        VerifyIssue(sha256=sha256, issue="orphan_blob") for sha256 in orphan_shas
    )
    checked = len(rows) + len(orphan_shas)
    return VerifyReport(
        checked=checked,
        ok=checked - len(issues),
        failed=len(issues),
        issues=issues,
    )
