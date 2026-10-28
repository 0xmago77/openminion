from __future__ import annotations

import io
import hashlib
import json
import os
from pathlib import Path
import tarfile
from uuid import uuid4

import pytest

from openminion.modules.runtime.sandboxes.docker_scan import DockerScanRunner
from openminion.modules.runtime.sandboxes.scan_config import DockerScanConfig
from openminion.base.config.env import EnvironmentConfig
from openminion.modules.artifact import ArtifactCtlError
from openminion.tools.security.offline import scan_snapshot_handler
from tests.tools.security.test_audit_report import audit_context  # noqa: F401

pytestmark = pytest.mark.e2e


@pytest.fixture
def offline_runner():
    if os.environ.get("OPENMINION_TEST_OFFLINE_SECURITY_SCAN") != "1":
        pytest.skip(
            "Set OPENMINION_TEST_OFFLINE_SECURITY_SCAN=1 for real scanner proof"
        )
    image = os.environ.get("OPENMINION_TEST_SECURITY_SCAN_IMAGE", "")
    socket = os.environ.get("OPENMINION_TEST_SECURITY_LAB_DOCKER_SOCKET", "")
    assert image and socket, (
        "Explicit offline scan tests require the prepared image and local Docker socket"
    )
    return DockerScanRunner(DockerScanConfig(daemon_socket=socket, worker_image=image))


def snapshot(path: Path, files: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_unchanged_archive_can_be_rescanned_in_a_fresh_session(
    offline_runner,
    audit_context,  # noqa: F811
):
    ctx, _ = audit_context
    archive = snapshot(ctx.workspace / "input.tar", {"app.py": b"eval(input())\n"})
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    config = ctx.run_root / "scan.json"
    config.write_text(
        json.dumps(
            {
                "docker": offline_runner.config.model_dump(mode="json"),
                "targets": {
                    "fixture": {"root": str(ctx.workspace), "kind": "source_snapshot"}
                },
            }
        )
    )
    ctx.env = EnvironmentConfig(values={"OPENMINION_SECURITY_SCAN_CONFIG": str(config)})
    ctx.tool_name = "security.scan_snapshot"
    args = dict(
        target_id="fixture", archive=str(archive), expected_sha256=digest, check="code"
    )
    creator = ctx.session_id
    for session in (creator, "fresh-" + uuid4().hex):
        ctx.session_id = session
        result = scan_snapshot_handler(args, ctx)
        assert result["status"] == "completed" and result["findings"]
        assert result["provenance"]["cleanup_completed"]
        assert digest not in ctx.artifactctl.index.active_reference_shas()
    assert ctx.artifactctl.get(digest).session_id == creator
    assert (
        ctx.artifactctl.read_bytes(digest, session_id=creator) == archive.read_bytes()
    )
    with pytest.raises(ArtifactCtlError, match="another session"):
        ctx.artifactctl.read_bytes(digest, session_id=ctx.session_id)
    assert ctx.artifactctl.list_views(digest) == []


_CASES = [
    (
        "ignored-source",
        "code",
        {"app.py": b"eval(input())\n", ".gitignore": b"*\n", ".semgrepignore": b"*\n"},
        {"app.py": b"print(input())\n", ".gitignore": b"*\n", ".semgrepignore": b"*\n"},
    ),
    ("python", "code", {"app.py": b"eval(input())\n"}, {"app.py": b"print(input())\n"}),
    (
        "javascript",
        "code",
        {"app.js": b"eval(userInput);\n"},
        {"app.js": b"console.log(userInput);\n"},
    ),
    (
        "python-dependencies",
        "dependencies",
        {"requirements.txt": b"flask==0.12\n"},
        {"requirements.txt": b"flask==3.1.3\n"},
    ),
    (
        "npm",
        "dependencies",
        {
            "package-lock.json": json.dumps(
                {
                    "name": "fixture",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"lodash": "4.17.20"}},
                        "node_modules/lodash": {
                            "version": "4.17.20",
                            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                        },
                    },
                }
            ).encode()
        },
        {
            "package-lock.json": json.dumps(
                {"name": "fixture", "lockfileVersion": 3, "packages": {}}
            ).encode()
        },
    ),
    (
        "terraform",
        "iac",
        {
            "main.tf": b'resource "aws_s3_bucket" "fixture" {\n bucket = "synthetic-fixture"\n acl = "public-read"\n}\n'
        },
        {"main.tf": b"# No cloud resources in the corrected synthetic fixture.\n"},
    ),
    (
        "dockerfile",
        "iac",
        {"Dockerfile": b"FROM alpine:3.10\nUSER root\n"},
        {"Dockerfile": b"FROM scratch\nUSER 10001\nHEALTHCHECK NONE\n"},
    ),
    (
        "secret",
        "secrets",
        {"fixture.env": b"GITHUB_TOKEN=ghp_123456789012345678901234567890123456\n"},
        {"fixture.env": b"# The synthetic token was removed.\n"},
    ),
]


@pytest.mark.parametrize(
    "name,check,vulnerable,corrected", _CASES, ids=[row[0] for row in _CASES]
)
def test_real_scanner_pairs(
    offline_runner, tmp_path, name, check, vulnerable, corrected
):
    counts = []
    for variant, files in (("vulnerable", vulnerable), ("corrected", corrected)):
        result = offline_runner.run(
            input_path=snapshot(tmp_path / f"{variant}.tar", files),
            session_id="offline-" + uuid4().hex,
            check=check,
            timeout=120,
        )
        assert result["cleanup_completed"]
        assert result["return_code"] in {0, 1}, result["stderr"]
        evidence = json.loads(result["stdout"])
        (tmp_path / f"{variant}.json").write_text(json.dumps(result, indent=2))
        if check == "code":
            count = len(evidence["results"])
            assert not evidence.get("errors"), evidence
        else:
            field = {
                "dependencies": "Vulnerabilities",
                "iac": "Misconfigurations",
                "secrets": "Secrets",
            }[check]
            count = sum(
                len(item.get(field) or []) for item in evidence.get("Results", [])
            )
        counts.append(count)
        assert offline_runner._command(
            "container", "inspect", result["worker_id"], check=False
        ).returncode
    assert counts[0] > 0, f"{name} vulnerable fixture was not detected"
    assert counts[1] == 0, f"{name} corrected fixture still has {counts[1]} findings"


def test_image_inventory_pair_and_truncation(offline_runner, tmp_path):
    from openminion.tools.security.archive_schemas import ArchiveScanArgs
    from openminion.tools.security.offline import normalize_worker_result
    from datetime import UTC, datetime
    from hashlib import sha256
    import time

    counts = []
    for variant, key in (
        ("vulnerable", "OPENMINION_TEST_SECURITY_VULNERABLE_IMAGE_ARCHIVE"),
        ("minimal", "OPENMINION_TEST_SECURITY_IMAGE_ARCHIVE"),
    ):
        value = os.environ.get(key)
        assert value, f"Explicit image fixture test requires {key}"
        archive = Path(value)
        assert archive.stat().st_size <= offline_runner.config.archive_bytes
        started = time.monotonic()
        result = offline_runner.run(
            input_path=archive,
            session_id="image-" + uuid4().hex,
            check="image",
            timeout=120,
        )
        args = ArchiveScanArgs(
            target_id="container-fixture",
            archive=str(archive),
            expected_sha256=sha256(archive.read_bytes()).hexdigest(),
        )
        scan = normalize_worker_result(
            result, args, "image", datetime.now(UTC).isoformat(), started
        )
        (tmp_path / f"{variant}.json").write_text(scan.model_dump_json(indent=2))
        assert scan.status in {"completed", "partial"}
        assert scan.truncated == (scan.total_findings > args.max_findings)
        assert scan.returned_findings <= args.max_findings
        counts.append(scan.total_findings)
    assert counts[0] > 0 and counts[1] == 0


def test_worker_deadline_survives_supervisor_loss_and_exact_recovery(
    offline_runner, tmp_path
):
    from hashlib import sha256
    import subprocess
    import sys
    import time
    from openminion.modules.artifact.control import ArtifactCtl
    from openminion.modules.runtime.sandboxes.docker import DockerSandboxError
    from openminion.tools.security.offline import recover_archive_scan
    from tests.artifact.utils import make_config
    from tests.artifact.test_retention import _age_all_artifacts

    archive = snapshot(
        tmp_path / "source.tar",
        {f"file{n}.py": b"value = 1\n" * 6553 for n in range(1000)},
    )
    digest = sha256(archive.read_bytes()).hexdigest()
    config = tmp_path / "scan.json"
    config.write_text(
        json.dumps(
            {
                "docker": offline_runner.config.model_dump(),
                "targets": {
                    "source": {"root": str(tmp_path), "kind": "source_snapshot"}
                },
            }
        )
    )
    session = "crash-" + uuid4().hex
    worker_name = (
        "openminion-security-scan-" + sha256(session.encode()).hexdigest()[:16]
    )
    child_code = """
import sys
from pathlib import Path
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.tool import RuntimeContext, Policy
from openminion.base.config.env import EnvironmentConfig
from openminion.tools.security.offline import scan_snapshot_handler
from tests.artifact.utils import make_config
root, config, session, digest = sys.argv[1:]
root = Path(root).resolve()
with ArtifactCtl(make_config(root / "cas")) as ctl:
    ctx = RuntimeContext(policy=Policy(raw={"workspace_root": str(root)}), workspace=root,
        run_root=root / "run", scope="READ_ONLY", confirm=False, permission_mode="readonly",
        session_id=session, artifactctl=ctl, env=EnvironmentConfig(values={"OPENMINION_SECURITY_SCAN_CONFIG": config}))
    scan_snapshot_handler(dict(target_id="source", archive=str(root / "source.tar"), expected_sha256=digest,
        check="code", timeout_seconds=2), ctx)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(tmp_path), str(config), session, digest],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    worker_id = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            found = offline_runner._command(
                "container", "inspect", worker_name, check=False
            )
            if found.returncode == 0:
                worker = json.loads(found.stdout)[0]
                if worker["State"]["Running"]:
                    worker_id = worker["Id"]
                    break
            assert child.poll() is None, child.stderr.read().decode()
            time.sleep(0.02)
        assert worker_id, "Worker never reached its running state"
        child.kill()
        child.wait(timeout=5)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            worker = json.loads(
                offline_runner._command("container", "inspect", worker_id).stdout
            )[0]
            if not worker["State"]["Running"]:
                break
            time.sleep(0.05)
        assert not worker["State"]["Running"]
        assert worker["State"]["ExitCode"] == 124
        with ArtifactCtl(make_config(tmp_path / "cas")) as ctl:
            _age_all_artifacts(ctl, 30)
            assert (
                digest
                not in ctl.gc(
                    plan_only=True, keep_days=0, delete_unreferenced_after_days=0
                ).candidates
            )
            with pytest.raises(DockerSandboxError, match="ownership"):
                offline_runner.recover(worker_id=worker_id, session_id="wrong-session")
            recovered = recover_archive_scan(
                docker_config=offline_runner.config,
                artifactctl=ctl,
                worker_id=worker_id,
                session_id=session,
            )
            assert not Path(recovered["input_path"]).exists()
            assert (
                digest
                in ctl.gc(
                    plan_only=True, keep_days=0, delete_unreferenced_after_days=0
                ).candidates
            )
            (tmp_path / "recovery.json").write_text(json.dumps(recovered))
        assert offline_runner._command(
            "container", "inspect", worker_id, check=False
        ).returncode
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stderr.close()
        if worker_id:
            offline_runner._command(
                "rm", "--force", "--volumes", worker_id, check=False
            )
