"""Provider-free contracts for the opt-in security harnesses."""

from dataclasses import replace
from contextlib import nullcontext
import json
import os
import sqlite3
import sys
import subprocess
from types import SimpleNamespace

import pytest

from openminion.cli.interactive.terminal.shell.approval import (
    format_terminal_approval_prompt,
)
from openminion.modules.artifact.config import (
    ArtifactCtlConfig,
    BlobStoreConfig,
    IndexConfig,
)
from openminion.modules.artifact.control import ArtifactCtl
from openminion.tools.security.plugin import _h_review_report
from openminion.tools.security.review_schemas import SecurityFindingReview
from tests.e2e.cli.focus.harness import FocusProbe
from tests.e2e.cli.focus import test_live_security_local_lab as lab
from tests.e2e.cli.focus import test_live_security_remediation as source
from tests.e2e.cli.focus.test_live_simple_input_project import (
    _assert_completed_child_lifecycle,
)
from tests.tools.security.test_audit_report import audit_context as audit_context
from tests.tools.security.test_review_report import _initial, _source, _reviewer

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    ("review_turn", "failed_tool", "code", "after_publish", "accepted"),
    [
        (False, "security.publish_report", "INVALID_ARGUMENT", False, True),
        (False, "security.publish_report", "POLICY_DENIED", False, False),
        (False, "security.publish_report", "EXEC_ERROR", False, False),
        (False, "security.scan_code", "INVALID_ARGUMENT", False, False),
        (False, "security.review_report", "INVALID_ARGUMENT", False, False),
        (False, "file.read", "POLICY_DENIED", False, False),
        (False, "security.publish_report", "INVALID_ARGUMENT", True, False),
        (True, "security.review_report", "INVALID_ARGUMENT", False, True),
        (True, "security.publish_report", "INVALID_ARGUMENT", False, False),
        (True, "security.review_report", "POLICY_DENIED", False, False),
        (True, "security.review_report", "EXEC_ERROR", False, False),
        (True, "security.review_report", "INVALID_ARGUMENT", True, False),
    ],
)
def test_source_publication_recovery_preserves_failure_boundaries(
    review_turn, failed_tool, code, after_publish, accepted
):
    def request(call_id, tool):
        return "tool.call.requested", {"call_id": call_id, "canonical_name": tool}

    def complete(call_id):
        return "tool.call.completed", {"call_id": call_id, "status": "success"}

    failure = [
        request("failed", failed_tool),
        (
            "tool.call.blocked",
            {"call_id": "failed", "status": "error", "error": {"code": code}},
        ),
    ]
    events = (
        [] if review_turn else [request("scan", "security.scan_code"), complete("scan")]
    )
    tool = "security.review_report" if review_turn else "security.publish_report"
    publication = [
        request("published", tool),
        complete("published"),
    ]
    events += publication + failure if after_publish else failure + publication
    expected = [tool] if review_turn else ["security.scan_code", tool]
    if accepted:
        assert source._assert_readonly_outcomes(events, expected, ["done"]) == [
            {"call_id": "failed", "tool_name": failed_tool, "error_code": code}
        ]
        # A second successful scan or publication still violates the lifecycle.
        with pytest.raises(AssertionError):
            source._assert_readonly_outcomes(
                events
                + [
                    request("duplicate", tool),
                    complete("duplicate"),
                ],
                expected,
                ["done"],
            )
    else:
        with pytest.raises(AssertionError):
            source._assert_readonly_outcomes(events, expected, ["done"])


@pytest.mark.parametrize(
    "terminal_statuses",
    [[], [None], ["error"], ["failed"], ["active"], ["done", "error"]],
)
def test_source_publication_requires_successful_terminal_turn(terminal_statuses):
    events = [
        (
            "tool.call.requested",
            {"call_id": "review", "canonical_name": "security.review_report"},
        ),
        ("tool.call.completed", {"call_id": "review", "status": "success"}),
    ]
    with pytest.raises(AssertionError, match="turn did not complete"):
        source._assert_readonly_outcomes(
            events, ["security.review_report"], terminal_statuses
        )


@pytest.fixture
def live_config(tmp_path, monkeypatch):
    original = tmp_path / "original.json"
    original.write_text(
        json.dumps(
            {
                "providers": {
                    "openai": {
                        "model": "MiniMax-M2.7",
                        "api_key_env": "MINIMAX_API_KEY",
                    }
                },
                "agents": {
                    "minimax-m2-7": {
                        "provider": "openai",
                        "command_policy": {
                            "allow": ["docker", "ssh", "open"],
                            "allow_host": True,
                        },
                    }
                },
                "runtime": {
                    "env": {
                        "MINIMAX_API_KEY": "unit-provider-credential",
                        "UNRELATED_SECRET": "must-stay-private",
                    }
                },
            }
        )
    )
    monkeypatch.delenv("MINIMAX_API_KEY", raising=False)
    monkeypatch.setenv("OPENMINION_CLI_FOCUS_E2E_CONFIG", str(original))
    monkeypatch.setenv("OPENMINION_CLI_FOCUS_E2E_AGENT", "minimax-m2-7")
    monkeypatch.setenv("OPENMINION_SECURITY_LIVE_MAX_TOKENS", "200")
    monkeypatch.setenv("OPENMINION_SECURITY_SEMGREP_EXECUTABLE", sys.executable)
    return original


@pytest.mark.parametrize("lane", ["source", "lab"])
def test_live_config_strips_secrets_and_broad_command_authority(
    live_config, tmp_path, monkeypatch, lane
):
    original = live_config.read_bytes()
    root = tmp_path / lane
    root.mkdir()
    if lane == "source":
        path, _, tokens = source._configuration(root, tmp_path / "target", monkeypatch)
        assert tokens == 200
    else:
        path, settings = lab._configuration(root, monkeypatch)
        assert settings["per_turn_token_limit"] == 200
    serialized = path.read_text()
    config = json.loads(serialized)
    assert "unit-provider-credential" not in serialized
    assert (
        "must-stay-private" not in serialized and "UNRELATED_SECRET" not in serialized
    )
    assert os.environ["MINIMAX_API_KEY"] == "unit-provider-credential"
    assert os.environ["OPENMINION_BRAIN_MAX_TOTAL_LLM_TOKENS"] == "200"
    assert path.stat().st_mode & 0o777 == 0o600
    assert live_config.read_bytes() == original
    for agent in config["agents"].values():
        assert not set(agent.get("command_policy", {}).get("allow", [])) & {
            "docker",
            "ssh",
            "open",
        }
    assert config["enabled_channels"] == ["console"]
    assert config["enabled_plugins"] == []


@pytest.mark.parametrize("lane", ["source", "lab"])
@pytest.mark.parametrize("cap", [None, "0", "-1"])
def test_explicit_live_run_requires_positive_token_input(
    live_config, tmp_path, monkeypatch, lane, cap
):
    monkeypatch.delenv("OPENMINION_SECURITY_LIVE_MAX_TOKENS", raising=False)
    if cap is not None:
        monkeypatch.setenv("OPENMINION_SECURITY_LIVE_MAX_TOKENS", cap)
    with pytest.raises(AssertionError, match="OPENMINION_SECURITY_LIVE_MAX_TOKENS"):
        if lane == "source":
            source._configuration(tmp_path, tmp_path / "target", monkeypatch)
        else:
            lab._configuration(tmp_path, monkeypatch)


def test_operator_reads_full_canonical_evidence_and_complete_handoff(
    audit_context, tmp_path, python_bin, openminion_root, framework_root
):
    ctx, revision = audit_context
    data = tmp_path / "data"
    artifact = data / "artifact"
    config = tmp_path / "config.json"
    config.write_text("{}")
    probe = FocusProbe(
        python_bin=python_bin,
        openminion_root=openminion_root,
        framework_root=framework_root,
        data_root=data,
        config_path=config,
        agent_id="reviewer",
        workdir=ctx.workspace,
        session_id="operator",
    )
    with ArtifactCtl(
        ArtifactCtlConfig(
            blob_store=BlobStoreConfig(root_dir=str(artifact)),
            index=IndexConfig(sqlite_path=str(artifact / "index.db")),
        )
    ) as ctl:
        ctx = replace(ctx, artifactctl=ctl)
        report_ref = _source(ctx, revision)
        review_ref = _h_review_report(_initial(report_ref), _reviewer(ctx))[
            "review_ref"
        ]
        documents = json.loads(
            source._operator_evidence(probe, ctl, [report_ref, review_ref]).split(
                "\n", 1
            )[1]
        )
        assert [item["ref"] for item in documents] == [report_ref, review_ref]
        assert documents[1]["metadata"]["agent_id"] == "reviewer"
        assert documents[1]["content"] == json.loads(ctl.read_bytes(review_ref))
        review = SecurityFindingReview.model_validate(documents[1]["content"])
        handoff = source._handoff(report_ref, review_ref, review, "python -B verify.py")
        approved = json.loads(handoff)
        assert len(handoff) <= 4000
        assert (
            approved["report_ref"] == report_ref
            and approved["review_ref"] == review_ref
        )
        assert (
            approved["base_revision"] == revision
            and approved["review_id"] == review.review_id
        )
        assert approved["remediation_brief"] == review.remediation_brief[0].model_dump(
            mode="json", exclude_none=True
        )
        assert approved["verification_timeout_seconds"] == 120 and approved["delivery"]
        assert (
            "edit only app.py using the existing file.write allowance"
            in approved["delivery"]
        )
        assert "leave verification to the runtime" in approved["delivery"]
        large = review.model_copy(deep=True)
        large.remediation_brief[0].verification_criteria = ["criterion" * 500]
        with pytest.raises(AssertionError, match="does not fit"):
            source._handoff(report_ref, review_ref, large, "python -B verify.py")
        ctl.delete(review_ref)
        with pytest.raises(subprocess.CalledProcessError):
            source._operator_evidence(probe, ctl, [review_ref])


def test_source_repair_schedules_persisted_focus_project_wake(
    live_config, tmp_path, monkeypatch, python_bin, openminion_root, framework_root
):
    target = tmp_path / "target"
    source._fixture(target)
    config, _, _ = source._configuration(tmp_path, target, monkeypatch)
    probe = FocusProbe(
        python_bin=python_bin,
        openminion_root=openminion_root,
        framework_root=framework_root,
        data_root=tmp_path / "data",
        config_path=config,
        agent_id=source._PARENT,
        workdir=target,
        session_id="repair-wake",
    )

    def inspect_before_wait(probe, run_id, _predicate, *, timeout):
        store, manager = source._project_owners(probe)
        sessions = source.SQLiteSessionStore(
            probe.data_root / "state/brain/sessions.db"
        )
        try:
            run = store.require(run_id)
            task = manager.get_task(run.task_id)
            job = sessions.get_cron_job(task.metadata["linked_cron_job_id"])
            assert job["agent_id"] == source._PARENT
            assert job["payload"] == {
                "kind": "projectCycle",
                "run_id": run_id,
                "task_id": run.task_id,
                "goal_id": run.goal_id,
                "session_id": probe.session_id,
                "user": "focus",
                "cycle_interval_seconds": 1,
            }
            assert run.continuation_policy.resume_on_daemon_restart
            assert 0 < timeout <= 660
        finally:
            sessions.close()
            manager.close()
        raise RuntimeError("stop before provider execution")

    monkeypatch.setattr(source, "_wait_for_run", inspect_before_wait)
    with pytest.raises(RuntimeError, match="stop before provider execution"):
        source._repair(probe, None, "approved finding F-1", "python -B verify.py")


def test_code_bearing_tool_evidence_keeps_success_distinct_from_child_status(tmp_path):
    database = tmp_path / "telemetry" / "telemetry.db"
    database.parent.mkdir()
    artifact = {"record_alias": "a2a-child:fixture", "target_digest": "digest"}
    outputs = [
        {"status": "success", "agent_id": "implementer", "child_artifact": artifact},
        {
            "status": "passed",
            "agent_id": "reviewer",
            "child_artifact": artifact,
            "review_receipt": {"findings": []},
        },
        {"status": "accepted", "target_digest": "digest"},
    ]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, agent_id TEXT, "
            "session_id TEXT, event_type TEXT, data TEXT)"
        )
        for mode, output in zip(("sync", "review", "accept"), outputs, strict=True):
            events = (
                (
                    "tool.call.requested",
                    {
                        "canonical_name": "task.delegate",
                        "sanitized_normalized_arguments": {
                            "mode": mode,
                            "child_artifact": artifact,
                        },
                    },
                ),
                (
                    "tool.call.completed",
                    {"status": "success", "output": {"outputs": output}},
                ),
            )
            for event, payload in events:
                connection.execute(
                    "INSERT INTO events (agent_id, session_id, event_type, data) VALUES (?, ?, ?, ?)",
                    (
                        "parent",
                        "session",
                        event,
                        json.dumps({"call_id": mode, **payload}),
                    ),
                )
    probe = SimpleNamespace(data_root=tmp_path, agent_id="parent", session_id="session")
    _, children, _ = source._tool_evidence(probe, after_event_id=0)
    assert [item["status"] for item in children] == ["success", "passed", "accepted"]
    _assert_completed_child_lifecycle(children, parent_agent_id="parent")
    children[0]["status"] = "completed"
    with pytest.raises(AssertionError):
        _assert_completed_child_lifecycle(children, parent_agent_id="parent")


def test_public_project_answer_returns_pending_report_and_persists_exact_reply(
    tmp_path, monkeypatch
):
    from tests.e2e.cli.focus.test_goal_composition import _CronStore, _project_runtime
    from tests.e2e.cli.focus.test_simple_input_project import _manager

    runtime, _, _ = _project_runtime(tmp_path)
    cron = _CronStore()
    monkeypatch.setattr(
        "openminion.cli.commands.autonomy_project.ensure_project_daemon_ready",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "openminion.cli.commands.autonomy_project.configured_cron_store",
        lambda *_args, **_kwargs: cron,
    )
    request = runtime.prepare_project_command(
        f"/project start --goal fixture --verify-command '{sys.executable} -c pass'"
    )
    assert runtime.launch_prepared_project(request)[0] == "system"
    run = request.run
    runtime.execute_project_control(f"/project pause {run.run_id}")
    manager = _manager(runtime)
    try:
        checkpoint_id, checkpoint = manager.get_latest_checkpoint(run.task_id)
        checkpoint["payload"]["pending_confirmation_command_id"] = "cmd-current"
        manager.save_checkpoint(run.task_id, checkpoint_id, checkpoint)
        for command in (
            f"/project show {run.run_id}",
            f"/project answer {run.run_id} --input-request-id cmd-current --answer allow_once",
        ):
            kind, output = runtime.execute_project_control(command)
            assert kind == "system" and "input_request_id: cmd-current" in output
            assert "operator_answers:" not in output
        answers = manager.get_task(run.task_id).metadata["operator_answers"]
        assert [(item["request_id"], item["answer"]) for item in answers] == [
            ("cmd-current", "allow_once")
        ]
        output = runtime.execute_project_control(f"/project resume {run.run_id}")[1]
        assert "task_state: active" in output
    finally:
        manager.close()


@pytest.mark.parametrize("changed", [None, "tool", "agent", "workspace", "id", "mode"])
@pytest.mark.parametrize("legacy_workspace", [None, "/unrelated-legacy-workspace"])
def test_project_approval_binds_pending_delegate_and_public_answer(
    tmp_path, monkeypatch, changed, legacy_workspace
):
    pending = {
        "command_id": "cmd-approved",
        "tool_name": "task.delegate",
        "args": {
            "mode": "sync",
            "agent_id": source._IMPLEMENTER,
            "code_bearing": True,
        },
    }
    if legacy_workspace is not None:
        pending["args"]["workspace_root"] = legacy_workspace
    if changed == "tool":
        pending["tool_name"] = "exec.run"
    elif changed == "id":
        pending["command_id"] = "cmd-other"
    elif changed in {"agent", "mode"}:
        field, value = {
            "agent": ("agent_id", "other"),
            "mode": ("mode", "accept"),
        }[changed]
        pending["args"][field] = value
    monkeypatch.setattr(
        source,
        "SQLiteSessionStore",
        lambda _path: SimpleNamespace(
            get_latest_working_state=lambda *_args, **_kwargs: {
                "state_inline": {"pending_confirmation_command": pending}
            },
            close=lambda: None,
        ),
    )
    controls = []
    markers = []

    def local_control(_session, command, *, marker):
        controls.append(command)
        markers.append(marker)
        return marker + "\nChoices: allow_once, allow_session, deny"

    monkeypatch.setattr(
        source,
        "_project_owners",
        lambda _: (
            None,
            SimpleNamespace(
                get_task=lambda _: SimpleNamespace(
                    metadata={
                        "operator_answers": [
                            {"request_id": "cmd-approved", "answer": "allow_once"}
                        ]
                    }
                ),
                close=lambda: None,
            ),
        ),
    )
    probe = SimpleNamespace(
        data_root=tmp_path / "data",
        workdir=tmp_path,
        session_id="session",
        session=lambda: nullcontext(None),
        wait_ready=lambda _: None,
        run_slash=local_control,
    )
    checkpoint = SimpleNamespace(
        payload={"pending_confirmation_command_id": "cmd-approved"},
        project_run=SimpleNamespace(
            project_run_id="project",
            workspace_ref=f"local:{tmp_path.parent if changed == 'workspace' else tmp_path}",
        ),
    )
    run = SimpleNamespace(run_id="run", task_id="task")
    if changed:
        with pytest.raises(AssertionError):
            source._approve_project_delegate(probe, None, run, checkpoint, "sync")
        assert not controls
    else:
        approval = source._approve_project_delegate(
            probe, None, run, checkpoint, "sync"
        )
        assert approval["reply"] == "allow_once"
        assert markers == [
            "input_request_id: cmd-approved",
            "input_request_id: cmd-approved",
            "task_state: active",
        ]
        assert controls == [
            "/project show run",
            "/project answer run --input-request-id cmd-approved --answer allow_once",
            "/project resume run",
        ]


@pytest.mark.parametrize("changed", [False, True])
def test_lab_approval_binds_complete_command_with_structural_arguments(
    tmp_path, monkeypatch, changed
):
    command = "curl --fail http://127.0.0.1:8000/defect"
    monkeypatch.setattr(
        lab,
        "_events",
        lambda *_: [
            {
                "execution_id": "exec-1",
                "agent_id": lab._AGENT,
                "event_type": "tool.call.requested",
                "data": {
                    "canonical_name": "exec.run",
                    "call_id": "call-1",
                    "sanitized_normalized_arguments": {},
                },
            }
        ],
    )
    shown = command + " --output leaked.txt" if changed else command
    screen = format_terminal_approval_prompt("exec.run", {"command": shown})
    probe = SimpleNamespace(data_root=tmp_path)
    if changed:
        with pytest.raises(AssertionError):
            lab._approve_command(probe, command, "inline", screen)
    else:
        lab._approve_command(probe, command, "inline", screen)


@pytest.mark.parametrize(
    "tool", ["security.review_report", "security.publish_report", "exec.run"]
)
def test_source_review_approves_only_review_report(tool):
    screen = format_terminal_approval_prompt(
        tool, {"report_ref": "artifact://sha256/" + "a" * 64}
    )
    if tool == "security.review_report":
        source._approve_review("inline", screen)
    else:
        with pytest.raises(AssertionError, match="unexpected approval"):
            source._approve_review("inline", screen)


def test_source_review_rejects_sidecar_consent():
    with pytest.raises(AssertionError, match="unexpected approval"):
        source._approve_review("sidecar", "Allow auto-start for PinchTab? [y/N]:")


@pytest.mark.parametrize("status", ["success", "failed"])
def test_tool_evidence_keeps_replay_completion_without_duplicating_native_calls(
    tmp_path, status
):
    database = tmp_path / "telemetry/telemetry.db"
    database.parent.mkdir()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, agent_id TEXT, session_id TEXT, event_type TEXT, data TEXT)"
        )
        rows = [
            (
                "tool.call.requested",
                {"call_id": "native", "canonical_name": "task.delegate"},
            ),
            ("tool.request", {"command_id": "native", "tool_name": "task.delegate"}),
            (
                "tool.completed",
                {
                    "command_id": "native",
                    "tool_name": "task.delegate",
                    "status": "success",
                },
            ),
            ("tool.call.completed", {"call_id": "native", "status": "success"}),
            ("tool.request", {"command_id": "replay", "tool_name": "task.delegate"}),
            (
                "tool.completed",
                {
                    "command_id": "replay",
                    "tool_name": "task.delegate",
                    "status": status,
                    "error": {"code": "DEPENDENCY_MISSING"}
                    if status == "failed"
                    else None,
                },
            ),
        ]
        connection.executemany(
            "INSERT INTO events (agent_id, session_id, event_type, data) VALUES (?, ?, ?, ?)",
            [
                (source._PARENT, "session", kind, json.dumps(data))
                for kind, data in rows
            ],
        )
    probe = SimpleNamespace(
        data_root=tmp_path, agent_id=source._PARENT, session_id="session"
    )
    calls, children, _ = source._tool_evidence(probe, after_event_id=0)
    assert [(item["event"], item["call_id"]) for item in calls] == [
        ("tool.call.requested", "native"),
        ("tool.call.completed", "native"),
        ("tool.request", "replay"),
        ("tool.completed", "replay"),
    ]
    assert calls[-1]["status"] == status
    assert calls[-1]["error_code"] == (
        "DEPENDENCY_MISSING" if status == "failed" else None
    )
    assert calls[-1]["mode"] is None
    assert [item["call_id"] for item in children] == ["native"]


@pytest.mark.parametrize(
    "change", [None, "failure", "args", "actor", "session", "duplicate", "extra"]
)
def test_replay_proof_binds_actual_session_records_to_approved_requests(
    tmp_path, change
):
    path = tmp_path / "state/brain/sessions.db"
    path.parent.mkdir(parents=True)
    sessions = source.SQLiteSessionStore(path)
    session_id = sessions.create_session(
        session_id="focus::conv:project", initial_agent_id=source._PARENT
    )
    approvals = []
    try:
        for mode in ("sync", "review", "accept"):
            args = {
                "mode": mode,
                "agent_id": "implementer" if mode == "sync" else "reviewer",
            }
            approvals.append(
                {"command_id": f"pending-{mode}", "mode": mode, "args": args}
            )
            lineage = {
                "command_id": f"replay-{mode}",
                "brain_session_id": session_id,
                "tool_name": "task.delegate",
            }
            actor = (
                "other-agent"
                if change == "actor" and mode == "sync"
                else source._PARENT
            )
            sessions.append_event(
                session_id,
                "brain.confirm_replay",
                {"command_id": lineage["command_id"]},
                actor_id=actor,
            )
            request = {
                **lineage,
                "args": {**args, "agent_id": "unapproved"}
                if change == "args" and mode == "sync"
                else args,
            }
            sessions.append_event(session_id, "tool.request", request, actor_id=actor)
            completed = {
                **lineage,
                "status": "failed"
                if change == "failure" and mode == "sync"
                else "success",
            }
            if change == "session" and mode == "sync":
                completed["brain_session_id"] = "another-session"
            sessions.append_event(
                session_id, "tool.completed", completed, actor_id=actor
            )
            if change == "duplicate" and mode == "sync":
                sessions.append_event(
                    session_id, "tool.completed", completed, actor_id=actor
                )
        if change == "extra":
            sessions.append_event(
                session_id,
                "brain.confirm_replay",
                {"command_id": "unapproved"},
                actor_id=source._PARENT,
            )
    finally:
        sessions.close()
    probe = SimpleNamespace(data_root=tmp_path, session_id="focus")
    if change:
        with pytest.raises(AssertionError):
            source._approved_replays(probe, "project", approvals)
    else:
        assert source._approved_replays(probe, "project", approvals) == [
            "replay-sync",
            "replay-review",
            "replay-accept",
        ]
