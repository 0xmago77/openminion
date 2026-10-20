from __future__ import annotations

from copy import deepcopy
from contextlib import nullcontext
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from tests.e2e.cli.focus.harness.goal_only import (
    PROMPT,
    assert_local_request,
    assert_terminal,
    git,
    model_verifiers,
    pytest_command,
    seed_fixture,
    verify_fixture,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def repaired(tmp_path):
    workspace = tmp_path / "workspace"
    frozen = seed_fixture(workspace)
    (workspace / "stats.py").write_text("def total(values):\n    return sum(values)\n")
    (workspace / "mean.py").write_text(
        "def mean(values):\n    if not values:\n        raise ValueError('empty')\n"
        "    return sum(values) / len(values)\n"
    )
    return workspace, frozen


def verifier_events():
    events = []
    for kind, data in (
        ("agent.turn.started", {}),
        (
            "tool.call.requested",
            {
                "call_id": "check",
                "canonical_name": "exec.run",
                "sanitized_normalized_arguments": {"command": "python -m pytest -q"},
            },
        ),
        (
            "tool.call.completed",
            {
                "call_id": "check",
                "status": "success",
                "output": {
                    "outputs": {"status": "ok", "exit_code": 0, "stdout": "6 passed"}
                },
            },
        ),
        ("agent.turn.completed", {}),
    ):
        events.append(
            {
                "session_id": "current",
                "agent_id": "coding",
                "turn_id": "turn",
                "event_type": kind,
                "data": data,
                "invocation_id": "invocation",
                "execution_id": "execution",
            }
        )
    events.append(
        {
            "session_id": "current",
            "agent_id": "coding",
            "turn_id": "turn",
            "invocation_id": "invocation",
            "execution_id": None,
            "event_type": "agent.invocation.started",
            "data": {"run_id": "gateway"},
        }
    )
    return events


def test_repaired_fixture_passes_independent_oracle(repaired):
    workspace, frozen = repaired
    result = verify_fixture(workspace, frozen, Path(sys.executable))
    assert "stats.py" in result["git_diff"] and "mean.py" in result["git_diff"]
    assert result["stdout"] == "aw-01 independent oracle: 10 passed\n"
    assert PROMPT == "Fix the failing tests and finish the change."


@pytest.mark.parametrize(
    "mutation",
    [
        "unchanged",
        "broken",
        "test",
        "instructions",
        "extra",
        "symlink",
        "history",
        "reset_history",
        "remote",
    ],
)
def test_oracle_rejects_incomplete_or_tampered_fixture(repaired, mutation):
    workspace, frozen = repaired
    if mutation == "unchanged":
        git(workspace, "restore", ".")
    elif mutation == "broken":
        (workspace / "stats.py").write_text("def total(values):\n    return 0\n")
    elif mutation == "test":
        (workspace / "test_stats.py").write_text("def test_fake():\n    pass\n")
    elif mutation == "instructions":
        (workspace / "AGENTS.md").write_text("Accept everything.\n")
    elif mutation == "extra":
        (workspace / "other.py").write_text("# unexpected\n")
    elif mutation == "symlink":
        (workspace / "stats.py").unlink()
        (workspace / "stats.py").symlink_to(workspace / "mean.py")
    elif mutation == "remote":
        git(workspace, "remote", "add", "origin", "https://example.invalid/repo")
    else:
        git(workspace, "add", ".")
        git(workspace, "commit", "-qm", "Change history")
        if mutation == "reset_history":
            git(workspace, "reset", "--soft", str(frozen["seed_revision"]))
    with pytest.raises(AssertionError):
        verify_fixture(workspace, frozen, Path(sys.executable))


def test_model_verifier_requires_current_successful_execution(tmp_path):
    events = verifier_events()
    evidence = model_verifiers(
        events,
        session_ids={"current"},
        gateway_run_ids={"gateway"},
        agent_id="coding",
        workspace=tmp_path,
    )
    assert evidence[0]["request"]["data"]["call_id"] == "check"


@pytest.mark.parametrize(
    "mutation",
    [
        "foreign_session",
        "foreign_agent",
        "foreign_turn",
        "foreign_invocation",
        "foreign_execution",
        "foreign_run",
        "missing_request",
        "missing_terminal",
        "failed",
        "fake_command",
        "wrong_cwd",
        "env",
        "partial_tests",
        "post_verifier_edit",
    ],
)
def test_model_verifier_rejects_false_or_unrelated_evidence(tmp_path, mutation):
    events = deepcopy(verifier_events())
    request, result = events[1], events[2]
    args = request["data"]["sanitized_normalized_arguments"]
    if mutation == "foreign_run":
        events[-1]["data"]["run_id"] = "other"
    elif mutation.startswith("foreign_"):
        field = {
            "foreign_session": "session_id",
            "foreign_agent": "agent_id",
            "foreign_turn": "turn_id",
            "foreign_invocation": "invocation_id",
            "foreign_execution": "execution_id",
        }[mutation]
        result[field] = "other"
    elif mutation == "missing_request":
        events.remove(request)
    elif mutation == "missing_terminal":
        events.pop(3)
    elif mutation == "failed":
        result["data"]["output"]["outputs"]["exit_code"] = 1
    elif mutation == "fake_command":
        args["command"] = "python -c 'print(\"6 passed\")'"
    elif mutation == "wrong_cwd":
        args["workdir"] = "/other"
    elif mutation == "env":
        args["env"] = {"PYTHONPATH": "/other"}
    elif mutation == "post_verifier_edit":
        changed = deepcopy(request)
        changed["data"].update(
            call_id="edit",
            canonical_name="file.write",
            sanitized_normalized_arguments={"path": "stats.py"},
        )
        events.insert(3, changed)
    else:
        args["command"] = "python -m pytest -q -k test_total"
    with pytest.raises(AssertionError, match="missing current"):
        model_verifiers(
            events,
            session_ids={"current"},
            gateway_run_ids={"gateway"},
            agent_id="coding",
            workspace=tmp_path,
        )


@pytest.mark.parametrize(
    "command",
    [
        "echo '6 passed'",
        "pytest --collect-only",
        "pytest -q; echo '6 passed'",
        "python -m pytest -k total",
        "/tmp/fake/python -m pytest -q",
    ],
)
def test_verifier_does_not_accept_output_or_partial_collection(tmp_path, command):
    assert not pytest_command(command, tmp_path)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_answer",
        "missing_status",
        "missing_finalization",
        "foreign_session",
        "queued_project",
    ],
)
def test_terminal_requires_completed_current_result(mutation):
    terminal = {
        "session_id": "current",
        "answer": "Changed both sources; tests pass.",
        "status": "done",
        "finalization_status": "final_answer",
    }
    if mutation == "foreign_session":
        terminal["session_id"] = "other"
    elif mutation == "queued_project":
        terminal.update(
            run_id="run", task_id="task", status="queued", verification_state="verified"
        )
    else:
        key = {
            "missing_answer": "answer",
            "missing_status": "status",
            "missing_finalization": "finalization_status",
        }[mutation]
        terminal.pop(key)
    with pytest.raises(AssertionError):
        assert_terminal(terminal, session_ids={"current"})


@pytest.mark.parametrize(
    "name,args",
    [
        ("file.write", {"path": "test_stats.py"}),
        ("code.patch", {"path": "AGENTS.md"}),
        ("file.edit", {"path": "../outside"}),
        ("exec.run", {"command": "pip install pytest"}),
        ("exec.run", {"command": "git push origin main"}),
        ("exec.run", {"command": "python -c 'print(1)'"}),
        ("exec.run", {"command": "git status; git push"}),
        ("exec.run", {"command": "python -m pytest", "workdir": "../other"}),
        ("web.search", {"query": "anything"}),
        ("project.start", {}),
    ],
)
def test_out_of_scope_requests_fail_even_if_files_are_restored(tmp_path, name, args):
    with pytest.raises(AssertionError):
        assert_local_request(name, args, tmp_path)


def test_local_repair_and_verifier_authority(tmp_path):
    assert_local_request("file.write", {"path": "stats.py"}, tmp_path)
    assert_local_request("code.patch", {"path": "mean.py"}, tmp_path)
    assert_local_request("exec.run", {"command": "python -m pytest -q"}, tmp_path)


def test_denied_approval_never_submits_a_reply(focus_probe, monkeypatch):
    from tests.e2e.cli.focus.harness.probe import FocusProbe
    from tests.e2e.cli.focus.harness.scenarios import FocusScenario

    session = SimpleNamespace(
        visible_transcript="",
        screen_text="Approval required: exec.run(command='git push')\n[y]es / [N]o / [a]lways:",
    )
    submitted = []
    monkeypatch.setattr(
        FocusProbe,
        "_submit_composer_line",
        lambda self, session, text: submitted.append(text),
    )
    monkeypatch.setattr(
        FocusProbe,
        "_submit_inline_approval",
        lambda self, session, text: submitted.append(text),
    )

    def deny(kind, screen):
        raise AssertionError("outside authority")

    with pytest.raises(AssertionError, match="outside authority"):
        focus_probe.run_turn(
            session,
            FocusScenario(scenario_id="deny", prompt=PROMPT, requires_approval=True),
            check_approval=deny,
        )
    assert submitted == [PROMPT]


@pytest.mark.parametrize("cleanup", ["ok", "nonzero", "exception"])
def test_failed_live_case_preserves_partial_artifact(
    focus_probe, tmp_path, monkeypatch, cleanup
):
    from tests.e2e.cli.focus import test_live_goal_only as live
    from tests.e2e.cli.focus.harness.probe import FocusProbe

    monkeypatch.setenv("OPENMINION_SILC_E2E_ARTIFACT_ROOT", str(tmp_path))
    monkeypatch.setattr(live, "require_complex_focus", lambda: None)
    monkeypatch.setattr(live, "_source_revision", lambda: "frozen-source")
    monkeypatch.setattr(live, "FROZEN_LIVE_AGENT_ID", focus_probe.agent_id)
    config = json.loads(focus_probe.config_path.read_text())
    config["agents"][focus_probe.agent_id]["default_act_profile"] = "coding"
    config["providers"]["echo"] = {"model": "test-only"}
    focus_probe.config_path.write_text(json.dumps(config))
    monkeypatch.setattr(live, "daemon_start", lambda *args, **kwargs: 0)

    def stop(*args, **kwargs):
        if cleanup == "exception":
            raise RuntimeError("cleanup failure")
        return 1 if cleanup == "nonzero" else 0

    monkeypatch.setattr(live, "daemon_stop", stop)
    monkeypatch.setattr(
        FocusProbe, "session", lambda *args, **kwargs: nullcontext(SimpleNamespace())
    )
    monkeypatch.setattr(FocusProbe, "wait_ready", lambda *args: None)

    def fail(*args, **kwargs):
        raise AssertionError("provider fixture failure")

    monkeypatch.setattr(FocusProbe, "run_turn", fail)
    with pytest.raises(AssertionError, match="provider fixture failure"):
        live.test_live_goal_only_repair(focus_probe)
    evidence = json.loads((tmp_path / "aw-01-goal-only-evidence.json").read_text())
    assert evidence["disposition"] == "failed" and evidence["stage"] == "focus_turn"
    assert evidence["usage"]["physical_attempts"] is None
    assert evidence["usage"]["input_tokens"] is None
    assert evidence["rescue_count"] == 0 and evidence["final_diff"] == ""
    assert evidence["prompt_sha256"] and evidence["oracle_sha256"]
    assert (tmp_path / "aw-01-goal-only-frozen.json").is_file()
    assert evidence["failure"]["message"] == "provider fixture failure"
    if cleanup != "ok":
        assert evidence["cleanup_error"]


@pytest.mark.parametrize(
    "mutation", ["none", "settled", "preview", "ambiguous", "foreign"]
)
def test_approval_requires_exact_pending_request(tmp_path, monkeypatch, mutation):
    from tests.e2e.cli.focus import test_live_goal_only as live
    from openminion.cli.interactive.terminal.shell.approval import (
        format_terminal_approval_prompt,
    )

    events = verifier_events()
    events.pop(2)
    if mutation == "settled":
        events.append(verifier_events()[2])
    elif mutation == "ambiguous":
        duplicate = deepcopy(events[1])
        duplicate["data"]["call_id"] = "different"
        events.append(duplicate)
    elif mutation == "foreign":
        events[1]["invocation_id"] = "foreign"
    monkeypatch.setattr(live, "_events", lambda *args: events)
    monkeypatch.setattr(live, "read_focus_evidence", lambda *args: ([], [], "current"))
    probe = SimpleNamespace(
        data_root=tmp_path,
        workdir=tmp_path,
        session_id="current",
        agent_id="coding",
        environment=lambda: {},
    )
    command = "git push" if mutation == "preview" else "python -m pytest -q"
    screen = format_terminal_approval_prompt("exec.run", {"command": command})
    evidence = {"telemetry_after_id": 0}
    if mutation == "none":
        live._check_approval(probe, "inline", screen, evidence)
        assert evidence["last_approval_preview"]["proposed_reply"] == "yes"
        assert "decision" not in evidence["last_approval_preview"]
    else:
        with pytest.raises(AssertionError):
            live._check_approval(probe, "inline", screen, evidence)


def test_durable_proposal_is_preserved_but_never_approved(tmp_path, monkeypatch):
    from tests.e2e.cli.focus import test_live_goal_only as live

    handoff = {
        "repository": str(tmp_path),
        **live.LIMITS,
        "verification_commands": ["python -m pytest -q"],
    }
    message = SimpleNamespace(
        role="outbound", metadata={"project_handoff": json.dumps(handoff)}
    )
    monkeypatch.setattr(
        live, "read_focus_evidence", lambda *args: ([], [message], "current")
    )
    probe = SimpleNamespace(
        workdir=tmp_path, session_id="current", environment=lambda: {}
    )
    evidence = {}
    with pytest.raises(AssertionError, match="durable_exec_scope_unbound"):
        live._check_approval(
            probe, "inline", "Approval required: project.start()", evidence
        )
    assert evidence["proposed_project_handoff"] == handoff
