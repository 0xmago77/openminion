from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
from types import SimpleNamespace
from uuid import uuid4

import pytest

from openminion.api.core.exposure import _security_lab_activation
from openminion.base.config.env import EnvironmentConfig
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.identity.runtime.service import IdentityCtl
from openminion.modules.identity.storage import InMemoryIdentityStore
from openminion.modules.tool.exposure import ToolExposureService
from openminion.modules.tool.runtime import RuntimeContext
from openminion.modules.tool.runtime.policy import Policy
from openminion.tools.exec.handlers import _h_exec_run
from openminion.tools.security.family import SECURITY_FAMILY
from openminion.tools.security.lab_metadata import resolve_security_lab_metadata
from openminion.tools.security.plugin import _h_publish_report
from tests.artifact.utils import make_config
from tests.e2e.security_lab.fixture import MALICIOUS_BODY, TARGET_BODY, local_lab
from tests.tools.security.test_local_lab import _active_report_payload, _lab_finding

pytestmark = pytest.mark.e2e


@pytest.fixture
def real_lab(tmp_path, monkeypatch):
    if os.environ.get("OPENMINION_TEST_DOCKER_SECURITY_LAB") != "1":
        pytest.skip(
            "Set OPENMINION_TEST_DOCKER_SECURITY_LAB=1 for real local Docker proof"
        )
    for key, name in (
        ("OPENMINION_HOME", "home"),
        ("OPENMINION_DATA_ROOT", "data"),
        ("OPENMINION_GENERATED_ROOT", "generated"),
    ):
        monkeypatch.setenv(key, str(tmp_path / name))
    with local_lab(tmp_path) as lab:
        yield lab


@pytest.fixture
def lab_context(real_lab, tmp_path):
    lab = real_lab
    session_id = "real-lab-" + uuid4().hex
    identityctl = IdentityCtl(store=InMemoryIdentityStore())
    identityctl.load_profiles_from_path(
        Path(__file__).resolve().parents[3]
        / "examples/identity/security-researcher-local-lab.yaml"
    )
    agent_id = lab.config.agent_identity_id
    profile = identityctl.get_profile(agent_id)
    summary = identityctl.get_profile_summary(agent_id)
    assert profile is not None and summary is not None
    identity = {
        "agent_id": agent_id,
        "profile_revision": profile.profile_revision,
        "profile_version": summary.profile_version,
        "tool_use": profile.tool_posture.tool_use,
        "allowed_tools": profile.tool_posture.allowed_tools,
        "lab_required": True,
    }
    identityctl.close()
    exposure = ToolExposureService(SECURITY_FAMILY.exposure_profiles)
    runtime = SimpleNamespace(
        config=SimpleNamespace(runtime=SimpleNamespace(security_lab=lab.config)),
        security_lab_runner=lab.runner,
        sessions=SimpleNamespace(
            get_session=lambda _: SimpleNamespace(
                session_key=f"agent:{agent_id}|channel:cli|target:test",
                owner_agent_id=agent_id,
            )
        ),
        resolve_agent_service=lambda _: SimpleNamespace(
            _identity_security_lab_facts=lambda: identity,
        ),
        tools=SimpleNamespace(exposure_service=exposure),
    )
    _security_lab_activation(
        runtime,
        session_id=session_id,
        target_id=lab.config.target_container,
        approved=True,
        ttl_seconds=300,
        activation_reason="Explicit real-Docker test opt-in",
        approved_by="local-test-operator",
        policy_source="pytest",
    )

    def metadata():
        return resolve_security_lab_metadata(
            exposure,
            config=lab.config,
            runner=lab.runner,
            identity=identity,
            session_id=session_id,
        )

    ctl = ArtifactCtl(make_config(tmp_path / "data"))
    ctx = RuntimeContext(
        policy=Policy(
            raw={"workspace_root": str(tmp_path), "context_metadata": metadata()}
        ),
        workspace=tmp_path,
        run_root=tmp_path / "run",
        scope="POWER_USER",
        confirm=True,
        env=EnvironmentConfig(values={}),
        artifactctl=ctl,
        permission_mode="ask",
        session_id=session_id,
        agent_id=agent_id,
        trace_id="real-docker-boundary",
        tool_name="exec.run",
        security_lab_runner=lab.runner,
        security_lab_metadata=metadata,
    )
    ctx.run_root.mkdir(parents=True, exist_ok=True)
    try:
        yield ctx
    finally:
        ctl.close()
        leaked = lab.docker(
            "ps",
            "-aq",
            "--filter",
            f"label=openminion.security_lab.session={session_id}",
        ).stdout.split()
        cleanup = [
            lab.docker("rm", "--force", "--volumes", worker, check=False)
            for worker in leaked
        ]
        assert not leaked, (
            f"Workers leaked: {leaked}; fixture cleanup exit codes: "
            f"{[result.returncode for result in cleanup]}"
        )


def _python(source: str) -> str:
    encoded = base64.b64encode(source.encode()).decode()
    return shlex.join(
        ["python3", "-B", "-c", f"exec(__import__('base64').b64decode('{encoded}'))"]
    )


def _execute(ctx, command: str, **arguments):
    ctx.tool_name = "exec.run"
    request = {
        "command": command,
        "timeout_s": 10,
        "include_evidence_artifact": True,
        **arguments,
    }
    result = _h_exec_run(request, ctx)
    ctx.run_root.mkdir(parents=True, exist_ok=True)
    with (ctx.run_root / "results.jsonl").open("a") as stream:
        stream.write(json.dumps({"request": request, "result": result}) + "\n")
    return result


def _stdout(ctx, result):
    return ctx.artifactctl.read_bytes(result["stdout_artifact"]["ref"])


def test_target_evidence_report_and_malicious_output(real_lab, lab_context, tmp_path):
    lab, ctx = real_lab, lab_context
    result = _execute(ctx, "curl --fail --silent --max-time 3 " + lab.target_url)
    assert result["status"] == "ok" and _stdout(ctx, result) == TARGET_BODY
    evidence_ref = result["evidence_artifact"]["ref"]
    evidence = json.loads(ctx.artifactctl.read_bytes(evidence_ref))
    assert evidence["execution"]["target_container_id"] == lab.target_id
    assert evidence["execution"]["worker_image_digest"] == lab.config.worker_image
    assert evidence["session_id"] == ctx.session_id
    assert evidence["agent_id"] == ctx.agent_id
    assert evidence["result"]["stdout"]["retained_bytes"] == len(TARGET_BODY)
    payload = _active_report_payload([evidence_ref])
    payload["findings"] = [_lab_finding(evidence_ref)]
    ctx.tool_name = "security.publish_report"
    published = _h_publish_report(payload, ctx)
    report = json.loads(ctx.artifactctl.read_bytes(published["report_ref"]))
    assert report["schema_version"] == "security-audit-report/v2"
    assert report["review_status"] == "unreviewed"
    assert report["findings"][0]["disposition"] == "candidate"
    malicious = _execute(ctx, "curl --fail --silent http://127.0.0.1:8080/binary")
    assert _stdout(ctx, malicious) == MALICIOUS_BODY
    assert "\x1b" not in malicious["stdout_preview"]
    assert "\\x1b" in malicious["stdout_preview"]
    assert malicious["stdout_preview"].startswith("[untrusted command output]")
    assert not lab.docker("diff", lab.target_id).stdout.strip()
    (tmp_path / "evidence.json").write_text(
        json.dumps(
            {
                "metadata": ctx.security_lab_metadata(),
                "execution": evidence,
                "report_ref": published["report_ref"],
                "malicious_output": malicious,
            },
            indent=2,
        )
    )


def test_network_and_host_isolation(real_lab, lab_context, tmp_path, monkeypatch):
    lab, ctx = real_lab, lab_context
    canary = tmp_path / "host-canary"
    canary.write_text("fixture-owned-host-secret")
    monkeypatch.setenv("OPENMINION_LAB_HOST_CANARY", "must-not-reach-worker")
    peer = lab.inspect("container", lab.peer_id)["NetworkSettings"]["Networks"][
        "bridge"
    ]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            connection, _ = listener.accept()
            connection.close()
        destinations = [
            ("1.1.1.1", 80),
            ("127.0.0.1", port),
            (peer["Gateway"], port),
            (peer["IPAddress"], 8080),
        ]
        result = _execute(
            ctx,
            _python(f"""
import json, socket
observed = []
for host, port in {destinations!r}:
    try:
        connection = socket.create_connection((host, port), timeout=0.5)
    except OSError:
        observed.append('denied')
    else:
        connection.close()
        observed.append('reachable')
print(json.dumps(observed))
"""),
        )
        assert result["status"] == "ok"
        assert json.loads(_stdout(ctx, result)) == ["denied"] * len(destinations)
        for host in ("example.com", "host.docker.internal"):
            result = _execute(
                ctx, f"curl --noproxy '*' --max-time 2 http://{host}:{port}/"
            )
            assert result["status"] == "error" and result["exit_code"] != 0
    boundary = _execute(
        ctx,
        _python(f"""
import json, os
from pathlib import Path
paths = [{str(canary)!r}, '/var/run/docker.sock', '/dev/mem', '/dev/sda']
print(json.dumps({{'visible': [p for p in paths if Path(p).exists()],
    'env': os.getenv('OPENMINION_LAB_HOST_CANARY'), 'uid': os.getuid(),
    'status': Path('/proc/self/status').read_text(),
    'workspace': list(Path('/workspace').iterdir())}}))
"""),
    )
    facts = json.loads(_stdout(ctx, boundary))
    assert facts["visible"] == [] and facts["env"] is None and facts["workspace"] == []
    assert facts["uid"] == 10001
    assert "CapEff:\t0000000000000000" in facts["status"]
    assert "NoNewPrivs:\t1" in facts["status"]
    assert canary.read_text() == "fixture-owned-host-secret"
    assert not lab.docker("diff", lab.target_id).stdout.strip()


def test_policy_limits_and_cleanup(real_lab, lab_context):
    lab, ctx = real_lab, lab_context
    command = "curl --silent " + lab.target_url
    for arguments in (
        {"host": "gateway"},
        {"background": True},
        {"pty": True},
        {"env": {"SECRET": "fixture"}},
        {"workdir": "/tmp"},
        {"security": "allowlist"},
        {"include_evidence_artifact": False},
        {"timeout_s": 11},
        {"command": command + " | cat"},
        {"command": "sh -c id"},
    ):
        result = _execute(ctx, **{"command": command, **arguments})
        assert (
            result["status"] == "denied" and result["error"]["code"] == "POLICY_DENIED"
        )
    for changes in ({"permission_mode": "readonly"}, {"confirm": False}):
        assert _execute(replace(ctx, **changes), command)["status"] == "denied"
    timeout = _execute(ctx, _python("import time\ntime.sleep(5)"), timeout_s=1)
    assert timeout["status"] == "timeout" and timeout["limit_reason"] == "timeout"
    output = _execute(ctx, _python("import sys\nsys.stdout.write('x' * 131072)"))
    assert output["output_limited"] is True and output["limit_reason"] == "output"
    assert len(_stdout(ctx, output)) <= lab.config.max_output_bytes
    memory = _execute(ctx, _python("bytearray(256 * 1024 * 1024)"))
    assert memory["limit_reason"] == "memory" and memory["terminated"] is True
    assert memory["error"]["code"] == "SANDBOX_RESOURCE_LIMIT"
    refs = []
    for limited in (timeout, output, memory):
        ref = limited["evidence_artifact"]["ref"]
        assert ref.startswith("artifact://sha256/")
        evidence = json.loads(ctx.artifactctl.read_bytes(ref))
        assert evidence["result"]["limit_reason"] == limited["limit_reason"]
        refs.append(ref)
    ctx.tool_name = "security.publish_report"
    partial = _h_publish_report(_active_report_payload(refs), ctx)
    assert partial["execution_status"] == "partial"
    scratch = _execute(
        ctx,
        _python(
            "from pathlib import Path\nPath('/workspace/marker').write_text('ephemeral')"
        ),
    )
    assert scratch["status"] == "ok"
    fresh = _execute(
        ctx,
        _python("from pathlib import Path\nprint(Path('/workspace/marker').exists())"),
    )
    assert _stdout(ctx, fresh).strip() == b"False"
    token = hashlib.sha256(ctx.session_id.encode()).hexdigest()[:12]
    stale = lab.docker(
        "create",
        "--name",
        f"openminion-security-lab-{token}",
        "--pull=never",
        "--label=openminion.test=security-lab",
        "--network=none",
        "--entrypoint=python3",
        lab.config.worker_image,
        "-V",
    ).stdout.strip()
    try:
        refused = _execute(ctx, command)
        assert refused["error"]["code"] == "SANDBOX_UNAVAILABLE"
        assert lab.inspect("container", stale)["State"]["Status"] == "created"
    finally:
        lab.docker("rm", "--force", "--volumes", stale)


def test_worker_enforces_filesystem_cpu_and_pid_limits(real_lab, lab_context):
    lab, ctx = real_lab, lab_context
    result = _execute(
        ctx,
        _python("""
import json, os, time
from pathlib import Path
root_error = 0
pid_error = 0
try:
    Path('/rootfs-probe').write_text('not allowed')
except OSError as error:
    root_error = error.errno
children = []
try:
    for index in range(64):
        pid = os.fork()
        if pid == 0:
            time.sleep(5)
            os._exit(0)
        children.append(pid)
except OSError as error:
    pid_error = error.errno
finally:
    for child in children:
        os.kill(child, 9)
        os.waitpid(child, 0)
deadline = time.monotonic() + 1
while time.monotonic() < deadline:
    pass
root = Path('/sys/fs/cgroup')
print(json.dumps({'root_error': root_error, 'pid_error': pid_error,
    'children': len(children), 'cpu': (root / 'cpu.max').read_text(),
    'memory': (root / 'memory.max').read_text(), 'pids': (root / 'pids.max').read_text(),
    'cpu_stats': (root / 'cpu.stat').read_text()}))
"""),
    )
    assert result["status"] == "ok", result
    facts = json.loads(_stdout(ctx, result))
    assert facts["root_error"] == 30 and facts["pid_error"] == 11
    assert facts["children"] < lab.config.pids_limit
    quota, period = map(int, facts["cpu"].split())
    assert quota / period == lab.config.cpu_limit
    assert int(facts["memory"]) == lab.config.memory_bytes
    assert int(facts["pids"]) == lab.config.pids_limit
    stats = dict(line.split() for line in facts["cpu_stats"].splitlines())
    assert int(stats["nr_throttled"]) > 0
