import hashlib
import io
import json
import tarfile

import pytest

from openminion.base.config.env import EnvironmentConfig
from openminion.modules.tool.errors import ToolRuntimeError
from openminion.tools.security.offline import scan_snapshot_handler
from openminion.tools.security.worker import image_identity, unpack_snapshot
from tests.tools.security.test_audit_report import audit_context  # noqa: F401


def archive_file(path, members):
    with tarfile.open(path, "w") as archive:
        for name, kind, content in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return path


def test_snapshot_admission_is_opaque_and_has_no_host_git(audit_context, monkeypatch):  # noqa: F811
    ctx, _ = audit_context
    archive = archive_file(
        ctx.workspace / "source.tar", [("app.py", tarfile.REGTYPE, b"print(1)")]
    )
    config = ctx.run_root / "scan.json"
    config.write_text(
        json.dumps(
            {
                "docker": {
                    "daemon_socket": "unix:///test.sock",
                    "worker_image": "sha256:" + "a" * 64,
                },
                "targets": {
                    "example": {"root": str(ctx.workspace), "kind": "source_snapshot"}
                },
            }
        )
    )
    ctx.env = EnvironmentConfig(values={"OPENMINION_SECURITY_SCAN_CONFIG": str(config)})
    ctx.tool_name = "security.scan_snapshot"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    calls = []

    def run(_runner, **kwargs):
        calls.append(kwargs)
        assert kwargs["input_path"].read_bytes() == archive.read_bytes()
        return dict(
            scanner="semgrep",
            scanner_version="1.0",
            scan_mode="code",
            config_sha256="b" * 64,
            database_sha256="",
            fixed_flags=["scan"],
            return_code=0,
            stdout='{"results": [], "errors": []}',
            stderr="",
            worker_id="c" * 64,
            worker_image_digest="sha256:" + "a" * 64,
            cleanup_completed=True,
        )

    monkeypatch.setattr("openminion.tools.security.offline.DockerScanRunner.run", run)
    monkeypatch.setattr(
        "openminion.tools.security.plugin._git_output",
        lambda *_: pytest.fail("host Git invoked"),
    )
    result = scan_snapshot_handler(
        dict(
            target_id="example",
            archive=str(archive),
            expected_sha256=digest,
            check="code",
        ),
        ctx,
    )
    assert result["status"] == "completed"
    assert result["target_identity"]["content_sha256"] == digest
    raw = ctx.artifactctl.get(digest)
    assert raw.meta_json["opaque"] is True
    assert ctx.artifactctl.list_views(digest) == []
    assert digest not in ctx.artifactctl.index.active_reference_shas()
    assert calls and not calls[0]["input_path"].exists()
    original_session = ctx.session_id
    ctx.session_id = "repeat-scan-session"
    repeated = scan_snapshot_handler(
        dict(
            target_id="example",
            archive=str(archive),
            expected_sha256=digest,
            check="code",
        ),
        ctx,
    )
    assert repeated["status"] == "completed"
    assert repeated["target_identity"] == result["target_identity"]
    assert ctx.artifactctl.get(digest).session_id == original_session
    assert digest not in ctx.artifactctl.index.active_reference_shas()
    with pytest.raises(ToolRuntimeError, match="digest"):
        scan_snapshot_handler(
            dict(
                target_id="example",
                archive=str(archive),
                expected_sha256="0" * 64,
                check="code",
            ),
            ctx,
        )
    ctx.artifactctl.config.blob_store.max_ingest_bytes = 10
    with pytest.raises(ToolRuntimeError, match="ingest limit"):
        scan_snapshot_handler(
            dict(
                target_id="example",
                archive=str(archive),
                expected_sha256=digest,
                check="code",
            ),
            ctx,
        )
    assert len(calls) == 2


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("link", tarfile.SYMTYPE),
        ("device", tarfile.CHRTYPE),
    ],
)
def test_source_archive_rejects_unsafe_entries(tmp_path, name, kind):
    archive = archive_file(tmp_path / "input.tar", [(name, kind, b"x")])
    with pytest.raises(ValueError, match="unsafe entry"):
        unpack_snapshot(archive, tmp_path / "source", 10, 100)
    assert not (tmp_path / "escape").exists()


def test_source_archive_bounds_and_single_image(tmp_path):
    archive = archive_file(
        tmp_path / "input.tar",
        [("one", tarfile.REGTYPE, b"a"), ("two", tarfile.REGTYPE, b"b")],
    )
    with pytest.raises(ValueError, match="limit"):
        unpack_snapshot(archive, tmp_path / "source", 1, 100)
    archive = archive_file(
        tmp_path / "image.tar",
        [("manifest.json", tarfile.REGTYPE, b'[{"Config":"one"},{"Config":"two"}]')],
    )
    with pytest.raises(ValueError, match="exactly one"):
        image_identity(archive, 10)


def test_docker_control_timeout_is_a_typed_failure(monkeypatch):
    import subprocess
    from openminion.modules.runtime.sandboxes.docker_scan import DockerScanRunner
    from openminion.modules.runtime.sandboxes.scan_config import DockerScanConfig
    from openminion.modules.runtime.sandboxes.docker import DockerSandboxError

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/false")
    runner = DockerScanRunner(
        DockerScanConfig(
            daemon_socket="unix:///test.sock", worker_image="sha256:" + "a" * 64
        )
    )

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 15)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(DockerSandboxError, match="could not complete"):
        runner._command("info")


def test_failed_worker_cleanup_preserves_exact_identity(tmp_path, monkeypatch):
    from openminion.modules.runtime.sandboxes.docker_scan import DockerScanRunner
    from openminion.modules.runtime.sandboxes.scan_config import DockerScanConfig
    from openminion.modules.runtime.sandboxes.docker import DockerSandboxError
    from subprocess import CompletedProcess

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/false")
    runner = DockerScanRunner(
        DockerScanConfig(
            daemon_socket="unix:///test.sock", worker_image="sha256:" + "a" * 64
        )
    )
    monkeypatch.setattr(runner, "preflight", lambda: "sha256:" + "a" * 64)
    monkeypatch.setattr(runner, "_create", lambda *args: "b" * 64)
    monkeypatch.setattr(runner, "_execute", lambda *args: {})

    def command(*args, **kwargs):
        if args[0] == "rm":
            raise DockerSandboxError("SANDBOX_UNAVAILABLE", "control timeout")
        return CompletedProcess(args, 1, b"", b"")

    monkeypatch.setattr(runner, "_command", command)
    with pytest.raises(DockerSandboxError) as failure:
        runner.run(
            input_path=tmp_path / "input.tar",
            session_id="fixture",
            check="code",
            timeout=1,
        )
    assert failure.value.details == {"worker_id": "b" * 64, "cleanup_completed": False}
