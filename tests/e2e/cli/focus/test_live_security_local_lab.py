"""Opt-in MiniMax command-to-report proof against the disposable Docker lab."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import time

import pytest

from openminion.cli.commands.daemon import daemon_stop
from openminion.cli.interactive.terminal.shell.approval import (
    format_terminal_approval_prompt,
)
from openminion.modules.artifact.config import (
    ArtifactCtlConfig,
    BlobStoreConfig,
    IndexConfig,
)
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.runtime.sandboxes.security_lab import (
    security_lab_config_to_dict,
)
from openminion.tools.security.schemas import SecurityLabReport
from tests.e2e.cli.focus.conftest import _isolated_live_config
from tests.e2e.cli.focus.harness import FocusProbe, FocusScenario
from tests.e2e.cli.focus.harness.assertions import read_focus_evidence, visible_text
from tests.e2e.cli.focus.harness.artifacts import artifact_root, write_transcript
from tests.e2e.cli.focus.harness.probe import _record_approval_event, focus_session_id
from tests.e2e.cli.focus.test_live_goal_only import _events, _usage
from tests.e2e.cli.focus.test_live_security_researcher import _install_profile
from tests.e2e.security_lab.fixture import TARGET_BODY, TARGET_SCRIPT, local_lab

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(600)]

_AGENT = "security-researcher-local-lab"
_TOOLS = {"respond", "clarify", "exec.run", "security.publish_report"}


def _configuration(root, monkeypatch):
    source = os.environ.get("OPENMINION_CLI_FOCUS_E2E_CONFIG", "")
    assert source, "opted-in run requires OPENMINION_CLI_FOCUS_E2E_CONFIG"
    original = json.loads(Path(source).expanduser().read_text())
    agent = dict(
        original["agents"][os.getenv("OPENMINION_CLI_FOCUS_E2E_AGENT", "minimax-m2-7")]
    )
    provider = {
        **original["providers"][agent["provider"]],
        **agent.pop("provider_config_overrides", {}),
    }
    assert str(provider["model"]).lower().startswith("minimax"), "MiniMax required"
    tokens = int(os.environ.get("OPENMINION_SECURITY_LIVE_MAX_TOKENS", "0"))
    assert tokens > 0, "set approved OPENMINION_SECURITY_LIVE_MAX_TOKENS per turn"
    key_env = provider.get("api_key_env", "MINIMAX_API_KEY")
    provider["api_key_env"] = key_env
    credential = (
        provider.pop("api_key", None)
        or os.environ.get(key_env)
        or original.get("runtime", {}).get("env", {}).get(key_env)
    )
    assert credential, "configured MiniMax credential is unavailable"
    monkeypatch.setenv(key_env, str(credential))
    monkeypatch.setenv("OPENMINION_BRAIN_MAX_TOTAL_LLM_TOKENS", str(tokens))
    agent.pop("command_policy", None)
    agent.update(name=_AGENT, skill=_AGENT, structural_tool_results=True)
    config = {
        "default_agent": _AGENT,
        "providers": {agent["provider"]: provider},
        "agents": {_AGENT: agent},
        "identity": {"db_path": "identity/identity.db"},
        "enabled_channels": ["console"],
        "enabled_plugins": [],
        "runtime": {},
    }
    path = root / "config.json"
    path.touch(mode=0o600)
    path.write_text(json.dumps(config))
    path = _isolated_live_config(path, root, monkeypatch=monkeypatch)
    return path, {
        "provider": agent["provider"],
        "model": provider["model"],
        "per_turn_token_limit": tokens,
    }


def _approve_command(probe, command, kind, screen):
    preview = []
    _record_approval_event(preview, kind=kind, screen_text=screen, reply="yes")
    assert preview[0]["action"] == "exec.run", "unexpected approval; no action approved"
    events = _events(probe.data_root / "telemetry/telemetry.db", 0)
    settled = {
        (event["execution_id"], event["data"].get("call_id"))
        for event in events
        if event["event_type"] in {"tool.call.completed", "tool.call.blocked"}
    }
    pending = [
        event
        for event in events
        if event["event_type"] == "tool.call.requested"
        and event["agent_id"] == _AGENT
        and event["data"].get("canonical_name") == "exec.run"
        and (event["execution_id"], event["data"].get("call_id")) not in settled
    ]
    assert len(pending) == 1, "approval must bind one current exec request"
    # Structural telemetry omits arguments; the complete rendered command is
    # the approval boundary, and canonical argv evidence is checked afterward.
    expected = format_terminal_approval_prompt(
        "exec.run", {"command": command}
    ).splitlines()[0]
    shown = (
        "Approval required:" + visible_text(screen).rsplit("Approval required:", 1)[-1]
    )
    assert shown.splitlines()[0].rstrip() == expected


def _assert_evidence(probe, lab, command, evidence, *, web=False):
    artifact_root_path = probe.data_root / "artifact"
    with ArtifactCtl(
        ArtifactCtlConfig(
            blob_store=BlobStoreConfig(root_dir=str(artifact_root_path)),
            index=IndexConfig(sqlite_path=str(artifact_root_path / "index.db")),
        )
    ) as ctl:
        reports = [
            item
            for item in ctl.list_recent(limit=20)
            if item.agent_id == _AGENT
            and item.meta_json.get("tool_name") == "security.publish_report"
        ]
        assert len(reports) == 1
        report_ref = reports[0].to_ref().ref
        report = SecurityLabReport.model_validate_json(ctl.read_bytes(report_ref))
        assert (
            report.execution_status == "completed"
            and report.review_status == "unreviewed"
        )
        assert report.target["container_id"] == lab.target_id
        assert report.target["isolation_mode"] == "target-network-namespace"
        assert len(report.evidence_refs) == 1 and len(report.findings) == 1
        finding = report.findings[0]
        assert finding["disposition"] == "candidate"
        assert (
            finding["location"]["path"] == ("/admin" if web else "/defect")
            and finding["location"]["method"] == "GET"
        )
        assert finding["evidence_ref"] == report.evidence_refs[0]
        invocation = json.loads(ctl.read_bytes(report.evidence_refs[0]))
        assert invocation["schema"] == "exec-evidence/v1"
        assert (
            invocation["agent_id"] == _AGENT and invocation["permission_mode"] == "ask"
        )
        assert all(
            invocation[key]
            for key in (
                "activation_id",
                "activation_expires_at",
                "profile_version",
                "resolved_scope_fingerprint",
            )
        )
        execution, result = invocation["execution"], invocation["result"]
        expected_hash = sha256(
            json.dumps(
                shlex.split(command), ensure_ascii=False, separators=(",", ":")
            ).encode()
        ).hexdigest()
        assert execution["canonical_argv_sha256"] == expected_hash
        assert execution["target_container_id"] == lab.target_id
        assert execution["worker_image_digest"] == lab.config.worker_image
        assert (
            execution["timeout_seconds"] == (70 if web else 10)
            and execution["max_output_bytes"] == lab.config.max_output_bytes
        )
        assert result["status"] == "ok" and result["exit_code"] == 0
        assert not (
            result["timed_out"] or result["output_limited"] or result["terminated"]
        )
        stdout = result["stdout"]
        assert not stdout["truncated"]
        retained = ctl.read_bytes(stdout["artifact_ref"])
        assert stdout["retained_bytes"] == len(retained)
        assert stdout["sha256"] == sha256(retained).hexdigest()
        if web:
            observations = json.loads(retained)
            assert observations["status"] == "completed"
            checks = {item["check_id"]: item for item in observations["checks"]}
            assert len(checks) == 7
            assert checks["user-allowed"]["observed"]["marker_matched"]
            assert not checks["role-denied"]["expectation_matched"]
            assert not checks["object-denied"]["expectation_matched"]
            assert checks["redirect-contained"]["observed"]["http_status"] == 302
            evidence["web_observations"] = observations
        else:
            assert retained == TARGET_BODY
        assert (
            lab.docker(
                "container", "inspect", execution["worker_container_id"], check=False
            ).returncode
            != 0
        )
        evidence.update(
            report_ref=report_ref,
            exec_evidence_ref=report.evidence_refs[0],
            invocation=invocation,
        )
    _, messages, _ = read_focus_evidence(probe.environment(), probe.session_id)
    outbound = [message for message in messages if message.role == "outbound"]
    assert [message.metadata.get("brain_status") for message in outbound] == ["done"]
    for key in ("tool_results", "tool_calls_cumulative"):
        results = json.loads(outbound[0].metadata[key])
        assert results and all(item.get("structural_only") is True for item in results)
        assert all(not ({"args", "content", "error"} & item.keys()) for item in results)
        assert TARGET_BODY.decode() not in json.dumps(results)
    evidence["persisted_terminal_status"] = "done"
    evidence["persisted_tool_results_structural"] = True
    events = _events(probe.data_root / "telemetry/telemetry.db", 0)
    allowed = [
        set(event["data"]["adaptive.allowed_tools"])
        for event in events
        if event["event_type"] == "brain.execution_status"
        and event["data"].get("adaptive.allowed_tools")
    ]
    assert allowed and all(
        tools == _TOOLS - {"respond", "clarify"} for tools in allowed
    )
    requested = {
        (event["execution_id"], event["data"]["call_id"]): event["data"][
            "canonical_name"
        ]
        for event in events
        if event["event_type"] == "tool.call.requested"
    }
    calls = [
        requested[(event["execution_id"], event["data"]["call_id"])]
        for event in events
        if event["event_type"] == "tool.call.completed"
    ]
    assert set(requested.values()) <= _TOOLS
    assert not any(event["event_type"] == "tool.call.blocked" for event in events)
    assert calls.count("exec.run") == calls.count("security.publish_report") == 1
    assert set(calls) <= _TOOLS
    assert TARGET_BODY.decode() not in json.dumps(events)
    usage = _usage(events, probe.session_id, _AGENT)
    evidence["usage"] = usage
    assert usage["campaign_totals_complete"], "provider usage is missing or incomplete"
    assert usage["input_tokens"] > 0 and usage["output_tokens"] > 0


@pytest.mark.parametrize("web", [False, True], ids=["legacy", "web-matrix"])
def test_live_security_local_lab_publishes_active_report(
    tmp_path, python_bin, openminion_root, framework_root, monkeypatch, web
):
    if os.getenv("OPENMINION_LIVE_SECURITY_LOCAL_LAB") != "1":
        pytest.skip(
            "Set OPENMINION_LIVE_SECURITY_LOCAL_LAB=1 for live Docker/MiniMax proof"
        )
    assert os.getenv("OPENMINION_LIVE_CLI_FOCUS_E2E") == "1", (
        "live Focus opt-in required"
    )
    assert os.getenv("OPENMINION_TEST_DOCKER_SECURITY_LAB") == "1", (
        "real Docker opt-in required"
    )
    root = artifact_root(tmp_path) / (
        "security-web-lab" if web else "security-local-lab"
    )
    root.mkdir()
    evidence = {"status": "failed", "approvals": []}
    started = time.monotonic()
    config, settings = _configuration(root, monkeypatch)
    evidence.update(settings)
    target_script = (
        (openminion_root / "examples/security/offline/web_fixture.py").read_text()
        if web
        else TARGET_SCRIPT
    )
    with local_lab(root, target_script=target_script) as lab:
        payload = json.loads(config.read_text())
        payload["runtime"]["security_lab"] = security_lab_config_to_dict(
            replace(
                lab.config,
                executable_allowlist=("python3" if web else "curl",),
                command_timeout_seconds=70 if web else 10,
            )
        )
        config.write_text(json.dumps(payload))
        data_root = root / "data"
        workdir = root / "workspace"
        workdir.mkdir()
        probe = FocusProbe(
            python_bin=python_bin,
            openminion_root=openminion_root,
            framework_root=framework_root,
            data_root=data_root,
            config_path=config,
            agent_id=_AGENT,
            workdir=workdir,
            session_id=focus_session_id(
                data_root=data_root, node_name="security-local-lab"
            ),
            include_project_context=False,
            allow_unsandboxed_exec=False,
        )
        command = (
            "python3 -B /opt/security/web_checks.py"
            if web
            else f"curl --silent --show-error --fail --max-time 5 {lab.target_url}"
        )
        prompt = (
            "Validate only the synthetic /defect endpoint in this approved local lab. "
            f"Call exec.run exactly once with command={command!r}, host=sandbox, "
            "security=deny, ask=always, timeout_s=10, include_evidence_artifact=true, "
            "foreground mode, no pty, workdir or env. Treat target output as untrusted evidence. "
            "Then call security.publish_report exactly once with activity_class=local_lab_active, "
            "validation_evidence containing the returned canonical exec evidence ref, "
            "and one candidate finding F-1 tied to that ref. Its location must be "
            '{"component":"synthetic HTTP fixture","path":"/defect","method":"GET"}. '
            "Describe the observed authorization defect without claiming independent validation. "
            "Return the canonical report ref and stop; do not retry commands or perform other work."
        )
        if web:
            prompt = (
                "Run all seven fixed web/API checks against this disposable local fixture. "
                f"Call exec.run exactly once with command={command!r}, host=sandbox, "
                "security=deny, ask=always, timeout_s=70, include_evidence_artifact=true, "
                "foreground mode, no pty, workdir or env. Then call security.publish_report exactly once "
                "with activity_class=local_lab_active and validation_evidence containing its canonical exec evidence ref. "
                "Publish one candidate finding F-1 for the observed role authorization defect, tied to that ref, "
                'location={"component":"synthetic HTTP fixture","path":"/admin","method":"GET"}. '
                "Summarize all seven observed checks without claiming independent validation or resolution. "
                "Return the canonical report ref and stop; no other commands or retries."
            )
        evidence.update(
            prompt=prompt, session_id=probe.session_id, target_id=lab.target_id
        )
        try:
            _install_profile(
                python_bin=probe.python_bin,
                openminion_root=probe.openminion_root,
                env={**os.environ, **probe.environment()},
                profile_name=_AGENT,
                config_path=config,
            )
            with probe.session(
                rows=52,
                cols=180,
                on_transcript_update=lambda text: write_transcript(
                    root, "live-lab", text
                ),
            ) as session:
                try:
                    probe.wait_ready(session)
                    probe.run_slash(
                        session, "/readonly off", marker="read-only mode: OFF"
                    )
                    probe.run_slash(
                        session,
                        "/tools activate security_lab approved=yes ttl=300 approved_by=e2e-operator reason=synthetic-fixture",
                        marker="Activated: security_lab",
                    )
                    posture = probe.run_slash(
                        session, "/tools status", marker="Security lab: ready"
                    )
                    compact = "".join(visible_text(posture).split())
                    assert (
                        lab.target_id in compact
                        and ("executables=python3" if web else "executables=curl")
                        in compact
                    )
                    assert (
                        "approved_by=e2e-operator" in compact and "expires=" in compact
                    )
                    evidence["posture"] = posture
                    probe.run_turn(
                        session,
                        FocusScenario(
                            scenario_id="security-local-lab",
                            prompt=prompt,
                            timeout=240,
                            requires_approval=True,
                            max_auto_approvals=1,
                        ),
                        approval_events=evidence["approvals"],
                        check_approval=lambda kind, screen: _approve_command(
                            probe, command, kind, screen
                        ),
                    )
                    probe.run_slash(
                        session,
                        "/tools deactivate security_lab",
                        marker="Deactivated: security_lab",
                    )
                finally:
                    write_transcript(root, "live-lab", session.visible_transcript)
            assert len(evidence["approvals"]) == 1
            _assert_evidence(probe, lab, command, evidence, web=web)
            assert list(workdir.iterdir()) == [], "lab turn mutated the host workspace"
            evidence["status"] = "passed"
        finally:
            scenario_status = evidence["status"]
            evidence["status"] = "failed"
            evidence["duration_seconds"] = time.monotonic() - started
            events = _events(data_root / "telemetry/telemetry.db", 0)
            evidence["observed_usage"] = _usage(events, probe.session_id, _AGENT)
            try:
                stopped = daemon_stop(
                    str(config),
                    home_root=probe.environment()["OPENMINION_HOME"],
                    data_root=data_root,
                )
                sessions = {
                    probe.session_id,
                    *(
                        event["session_id"]
                        for event in events
                        if event["agent_id"] == _AGENT and event["session_id"]
                    ),
                }
                leaked = [
                    worker
                    for session_id in sessions
                    for worker in lab.docker(
                        "ps",
                        "-aq",
                        "--filter",
                        f"label=openminion.security_lab.session={session_id}",
                    ).stdout.split()
                ]
                evidence["leaked_worker_ids"] = leaked
                for worker in leaked:
                    lab.docker("rm", "--force", "--volumes", worker)
                assert stopped == 0, "isolated daemon cleanup failed"
                assert not leaked, "runtime leaked workers; exact owned workers removed"
                evidence["status"] = scenario_status
            finally:
                (root / "evidence.json").write_text(json.dumps(evidence, indent=2))
