from __future__ import annotations

from dataclasses import replace
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

from tests.e2e.security_lab import fixture
from tests.e2e.security_lab.test_local_lab import _execute, _python
from tests.tools.security.test_local_lab import lab_context as lab_context

pytestmark = pytest.mark.e2e
_IMAGE = "fixture.invalid/image@sha256:" + "a" * 64


def test_opt_out_never_invokes_docker(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENMINION_TEST_DOCKER_SECURITY_LAB", raising=False)
    monkeypatch.setattr(
        fixture.subprocess, "run", lambda *a, **kw: pytest.fail("Docker called")
    )
    with pytest.raises(pytest.skip.Exception):
        with fixture.local_lab(tmp_path):
            pytest.fail("Opt-out reached the fixture")


def test_explicit_run_fails_missing_inputs_before_docker(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENMINION_TEST_DOCKER_SECURITY_LAB", "1")
    for suffix in ("DOCKER_SOCKET", "TARGET_IMAGE", "WORKER_IMAGE"):
        monkeypatch.delenv("OPENMINION_TEST_SECURITY_LAB_" + suffix, raising=False)
    monkeypatch.setattr(
        fixture.subprocess, "run", lambda *a, **kw: pytest.fail("Docker called")
    )
    with pytest.raises(
        pytest.fail.Exception, match="DOCKER_SOCKET.*TARGET_IMAGE.*WORKER_IMAGE"
    ):
        with fixture.local_lab(tmp_path):
            pytest.fail("Missing prerequisites admitted")


def test_nonlocal_socket_is_refused_before_docker(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "OPENMINION_TEST_SECURITY_LAB_DOCKER_SOCKET", "tcp://localhost:2375"
    )
    monkeypatch.setenv("OPENMINION_TEST_SECURITY_LAB_TARGET_IMAGE", _IMAGE)
    monkeypatch.setenv("OPENMINION_TEST_SECURITY_LAB_WORKER_IMAGE", _IMAGE)
    monkeypatch.setattr(
        fixture.subprocess, "run", lambda *a, **kw: pytest.fail("Docker called")
    )
    with pytest.raises(AssertionError, match="local Unix"):
        fixture._required_inputs()


def test_unpinned_image_is_refused_before_docker(tmp_path, monkeypatch):
    path = tmp_path / "daemon.sock"
    monkeypatch.setattr(fixture.Path, "is_socket", lambda self: self == path)
    monkeypatch.setenv(
        "OPENMINION_TEST_SECURITY_LAB_DOCKER_SOCKET", "unix://" + str(path)
    )
    monkeypatch.setenv("OPENMINION_TEST_SECURITY_LAB_TARGET_IMAGE", "target:latest")
    monkeypatch.setenv("OPENMINION_TEST_SECURITY_LAB_WORKER_IMAGE", _IMAGE)
    monkeypatch.setattr(
        fixture.subprocess, "run", lambda *a, **kw: pytest.fail("Docker called")
    )
    with pytest.raises(AssertionError, match="digest-pinned"):
        fixture._required_inputs()


def test_probe_command_uses_direct_argv_and_canonical_evidence(lab_context):
    ctx, runner, ordinary = lab_context
    runner.config = replace(runner.config, executable_allowlist=("python3",))
    result = _execute(ctx, _python("import json\nprint(json.dumps({'probe': True}))"))
    assert result["status"] == "ok"
    assert runner.calls[0][0].cmd[:3] == ["python3", "-B", "-c"]
    assert ordinary.calls == []
    assert ctx.artifactctl.read_bytes(result["evidence_artifact"]["ref"])


@pytest.mark.parametrize("fail_at", [1, 2, None])
def test_cleanup_only_removes_created_ids_even_when_readiness_fails(
    tmp_path, monkeypatch, fail_at
):
    monkeypatch.setenv("OPENMINION_TEST_DOCKER_SECURITY_LAB", "1")
    monkeypatch.setattr(
        fixture,
        "_required_inputs",
        lambda: ("/test/docker", "unix:///test.sock", _IMAGE, _IMAGE),
    )
    closed = []
    runner = SimpleNamespace(preflight=lambda: None, close=lambda: closed.append(True))
    monkeypatch.setattr(fixture, "DockerSandboxRunner", lambda *a, **kw: runner)
    monkeypatch.setattr(
        fixture.LocalLab,
        "inspect",
        lambda *a: {"Id": "sha256:" + "a" * 64, "RepoDigests": [_IMAGE], "Config": {}},
    )
    created, removed = [], []

    def docker(self, *args, check=True):
        if args[0] == "info":
            return CompletedProcess(args, 0, "2\n", "")
        if args[0] == "create":
            created.append("owned-" + str(len(created) + 1))
            return CompletedProcess(args, 0, created[-1], "")
        if args[0] == "rm":
            removed.append(args[-1])
            return CompletedProcess(args, 0, "", "")
        assert args[:2] == ("container", "inspect") and args[-1] in removed
        return CompletedProcess(args, 1, "", "not found")

    monkeypatch.setattr(fixture.LocalLab, "docker", docker)

    def ready(lab, container_id):
        if len(created) == fail_at:
            raise RuntimeError("fixture failed to start")

    monkeypatch.setattr(fixture, "_wait_ready", ready)
    if fail_at:
        with pytest.raises(RuntimeError, match="failed to start"):
            with fixture.local_lab(tmp_path):
                pytest.fail("Readiness failure admitted")
    else:
        with fixture.local_lab(tmp_path):
            assert removed == []
    assert removed == created[::-1]
    assert closed == [True]
