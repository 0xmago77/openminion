from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

import pytest

from openminion.cli.commands.daemon import daemon_start, daemon_stop
from openminion.cli.interactive.terminal.shell.approval import (
    format_terminal_approval_prompt,
)
from tests.e2e.cli.focus.conftest import require_complex_focus
from tests.e2e.cli.focus.harness.assertions import read_focus_evidence
from tests.e2e.cli.focus.harness.artifacts import write_transcript
from tests.e2e.cli.focus.harness.goal_only import (
    ALLOWED_APPROVALS,
    FIXTURE,
    LIMITS,
    PROMPT,
    READ_ONLY_COMMANDS,
    SCENARIO_ID,
    assert_local_request,
    assert_terminal,
    model_verifiers,
    pytest_command,
    seed_fixture,
    verify_fixture,
)
from tests.e2e.cli.focus.harness.probe import _record_approval_event
from tests.e2e.cli.focus.harness.scenarios import FocusScenario
from tests.e2e.cli.focus.test_live_simple_input_project import (
    FROZEN_LIVE_AGENT_ID,
    _project_owners,
    _source_revision,
    _telemetry_cursor,
)

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(1050)]


def _events(path: Path, after_id: int) -> list[dict]:
    if not path.is_file():
        return []
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, session_id, agent_id, turn_id, invocation_id, execution_id, "
            "event_type, data FROM events WHERE id > ? ORDER BY id",
            (after_id,),
        ).fetchall()
    return [{**dict(row), "data": json.loads(row["data"])} for row in rows]


def _project_limits(handoff: dict, workspace: Path) -> None:
    assert Path(handoff.get("repository") or workspace).resolve() == workspace, (
        "project repository differs from the fixture"
    )
    for field, ceiling in LIMITS.items():
        value = handoff.get(field)
        assert isinstance(value, int) and 0 < value <= ceiling, (
            f"project {field} is absent or exceeds the frozen ceiling"
        )
    assert handoff["max_iterations"] >= 2
    assert handoff.get("verification_commands"), "project verifier missing"
    assert all(
        pytest_command(command, workspace)
        for command in handoff["verification_commands"]
    ), "project verifier outside frozen whole-fixture authority"


def _check_approval(probe, kind: str, screen: str, evidence: dict) -> None:
    preview: list[dict[str, object]] = []
    _record_approval_event(preview, kind=kind, screen_text=screen, reply="yes")
    action = preview[0]["action"]
    preview[0].pop("decision")
    preview[0]["proposed_reply"] = "yes"
    evidence["last_approval_preview"] = preview[0]
    assert action in ALLOWED_APPROVALS, f"unplanned approval: {action}"
    if action == "project.start":
        _, messages, _ = read_focus_evidence(probe.environment(), probe.session_id)
        handoffs = [
            message.metadata["project_handoff"]
            for message in messages
            if message.role == "outbound" and message.metadata.get("project_handoff")
        ]
        assert len(handoffs) == 1, "missing or ambiguous typed project handoff"
        handoff = json.loads(handoffs[0])
        _project_limits(handoff, probe.workdir)
        evidence["proposed_project_handoff"] = handoff
        raise AssertionError(
            "durable_exec_scope_unbound: future project exec cannot be bound by the Focus approval callback"
        )
    events = _events(
        probe.data_root / "telemetry" / "telemetry.db", evidence["telemetry_after_id"]
    )
    _, _, brain_session_id = read_focus_evidence(probe.environment(), probe.session_id)
    invocation_ids = {
        event["invocation_id"]
        for event in events
        if event["event_type"] == "agent.invocation.started"
        and event["session_id"] == probe.session_id
        and event["agent_id"] == probe.agent_id
    }
    assert len(invocation_ids) == 1, "missing or ambiguous current approval invocation"
    settled = {
        (event["invocation_id"], event["execution_id"], event["data"].get("call_id"))
        for event in events
        if event["event_type"] in {"tool.call.completed", "tool.call.blocked"}
    }
    requests = [
        event
        for event in events
        if event["event_type"] == "tool.call.requested"
        and event["agent_id"] == probe.agent_id
        and event["data"].get("canonical_name") == action
        and event["session_id"] == brain_session_id
        and event["invocation_id"] in invocation_ids
        and event["execution_id"]
        and (
            event["invocation_id"],
            event["execution_id"],
            event["data"].get("call_id"),
        )
        not in settled
    ]
    assert len(requests) == 1, "approval has no unique pending current tool request"
    request = requests[0]
    args = request["data"]["sanitized_normalized_arguments"]
    expected = format_terminal_approval_prompt(str(action), args).splitlines()[0]
    shown = "Approval required:" + screen.rsplit("Approval required:", 1)[-1]
    assert "".join(expected.split()) in "".join(shown.split()), (
        "approval preview differs from pending request"
    )
    evidence["last_approval_request"] = request
    assert_local_request(action, args, probe.workdir)


def _usage(events: list[dict], session_id: str, agent_id: str) -> dict:
    timings = [
        event
        for event in events
        if event["event_type"] == "chat.phase_timing"
        and event["data"].get("session_id") == session_id
        and event["data"].get("agent_id") == agent_id
    ]
    fields = {"provider_attempts", "provider_input_tokens", "provider_output_tokens"}
    complete = bool(timings) and all(
        fields <= event["data"].keys()
        and isinstance(event["data"]["provider_attempts"], list)
        and bool(event["data"]["provider_attempts"])
        and isinstance(event["data"]["provider_input_tokens"], int)
        and isinstance(event["data"]["provider_output_tokens"], int)
        for event in timings
    )
    return {
        "scope": "focus_parent_session",
        "timing_records": timings,
        "physical_attempts": [
            attempt
            for event in timings
            for attempt in event["data"]["provider_attempts"]
        ]
        if complete
        else None,
        "input_tokens": sum(event["data"]["provider_input_tokens"] for event in timings)
        if complete
        else None,
        "output_tokens": sum(
            event["data"]["provider_output_tokens"] for event in timings
        )
        if complete
        else None,
        "campaign_totals_complete": complete,
    }


def test_live_goal_only_repair(focus_probe) -> None:
    require_complex_focus()
    root = Path(os.environ["OPENMINION_SILC_E2E_ARTIFACT_ROOT"]).resolve()
    workspace = root / "workspaces" / SCENARIO_ID
    frozen = seed_fixture(workspace)
    probe = focus_probe.for_workdir(workspace)
    source_revision = _source_revision()
    config = json.loads(probe.config_path.read_text())
    agent = config["agents"][probe.agent_id]
    assert probe.agent_id == FROZEN_LIVE_AGENT_ID
    assert agent.get("default_act_profile") == "coding"
    provider = {
        **config["providers"][agent["provider"]],
        **agent.get("provider_config_overrides", {}),
    }
    evidence = {
        "scenario_id": SCENARIO_ID,
        "source_revision": source_revision,
        "config_sha256": sha256(probe.config_path.read_bytes()).hexdigest(),
        "profile": probe.agent_id,
        "act_profile": agent.get("default_act_profile"),
        "provider": agent["provider"],
        "model": provider["model"],
        "prompt": PROMPT,
        **frozen,
        "limits": LIMITS,
        "campaign_deadline_seconds": 900,
        "approved_action_classes": ALLOWED_APPROVALS,
        "approval_ceiling": 8,
        "direct_read_only_commands": READ_ONLY_COMMANDS,
        "verifier_authority": "direct python -m pytest or pytest, whole fixture; no environment override",
        "durable_authority": "fail closed before reply: future project exec scope is unbound",
        "execution_backend": "host_unconfined",
        "rescue_count": 0,
        "stage": "daemon_start",
        "disposition": "incomplete",
        "approvals": [],
        "usage": None,
        "terminal": None,
        "model_verifiers": [],
        "telemetry_after_id": 0,
    }
    evidence_path = root / f"{SCENARIO_ID}-evidence.json"
    frozen_path = root / f"{SCENARIO_ID}-frozen.json"
    frozen_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    started = time.monotonic()
    deadline = started + 900
    after_id = 0
    telemetry_path = probe.data_root / "telemetry" / "telemetry.db"
    home_root = probe.data_root.parent / "home-roots" / probe.session_id
    try:
        assert (
            daemon_start(
                str(probe.config_path), home_root=home_root, data_root=probe.data_root
            )
            == 0
        )
        evidence["stage"] = "focus_turn"
        with probe.session(
            rows=60,
            cols=200,
            on_transcript_update=lambda text: write_transcript(root, SCENARIO_ID, text),
        ) as session:
            probe.wait_ready(session)
            after_id = _telemetry_cursor(probe)
            evidence["telemetry_after_id"] = after_id
            probe.run_turn(
                session,
                FocusScenario(
                    scenario_id=SCENARIO_ID,
                    prompt=PROMPT,
                    timeout=max(1, int(deadline - time.monotonic())),
                    requires_approval=True,
                    max_auto_approvals=8,
                    approval_reply="yes",
                    max_auto_continuations=0,
                ),
                approval_events=evidence["approvals"],
                check_approval=lambda kind, screen: _check_approval(
                    probe, kind, screen, evidence
                ),
            )
        evidence["stage"] = "terminal_readback"
        _, messages, brain_session_id = read_focus_evidence(
            probe.environment(), probe.session_id
        )
        session_ids = {probe.session_id, brain_session_id}
        store, manager = _project_owners(probe)
        try:
            assert not store.list_runs(limit=None), (
                "project launched outside frozen authority"
            )
        finally:
            manager.close()
        outbound = [message for message in messages if message.role == "outbound"]
        assert len(outbound) == 1, "missing or ambiguous current recorded answer"
        message = outbound[0]
        finalization = json.loads(
            message.metadata.get("adaptive.finalization_status", "{}")
        )
        terminal = {
            "session_id": message.session_id,
            "message_id": message.id,
            "gateway_run_id": message.metadata.get("run_id"),
            "request_id": message.metadata.get("request_id"),
            "status": message.metadata.get("brain_status"),
            "answer": message.body,
            "finalization_status": finalization.get("status"),
        }
        evidence["terminal"] = terminal
        assert_terminal(terminal, session_ids=session_ids)
        assert time.monotonic() < deadline, "campaign deadline exceeded"
        evidence["stage"] = "model_verification"
        events = _events(telemetry_path, after_id)
        gateway_run_ids = {
            message.metadata["run_id"]
            for message in messages
            if message.role == "outbound" and message.metadata.get("run_id")
        }
        assert gateway_run_ids, "missing current gateway run identity"
        evidence["gateway_run_ids"] = sorted(gateway_run_ids)
        for event in events:
            if event["event_type"] == "tool.call.requested":
                assert_local_request(
                    event["data"]["canonical_name"],
                    event["data"]["sanitized_normalized_arguments"],
                    workspace,
                )
        evidence["model_verifiers"] = model_verifiers(
            events,
            session_ids=session_ids,
            gateway_run_ids=gateway_run_ids,
            agent_id=probe.agent_id,
            workspace=workspace,
        )
        evidence["stage"] = "independent_verification"
        evidence["independent_verification"] = verify_fixture(
            workspace, frozen, probe.python_bin
        )
        evidence["source_revision_end"] = _source_revision()
        assert evidence["source_revision_end"] == source_revision
        assert time.monotonic() < deadline, (
            "campaign deadline exceeded during verification"
        )
        evidence["usage"] = _usage(events, probe.session_id, probe.agent_id)
        assert evidence["usage"]["campaign_totals_complete"], (
            "provider accounting incomplete"
        )
        evidence.update(stage="complete", disposition="pass")
    except Exception as exc:
        evidence.update(
            disposition="failed",
            failure={"type": type(exc).__name__, "message": str(exc)},
        )
        raise
    finally:
        cleanup_error = None
        try:
            cleanup_result = daemon_stop(
                str(probe.config_path), home_root=home_root, data_root=probe.data_root
            )
            assert cleanup_result == 0, f"daemon stop failed: {cleanup_result}"
        except Exception as exc:
            cleanup_error = str(exc)
            evidence["cleanup_error"] = cleanup_error
        finally:
            try:
                events = _events(telemetry_path, after_id)
            except sqlite3.Error as exc:
                events = []
                evidence["telemetry_read_error"] = str(exc)
            evidence["usage"] = _usage(events, probe.session_id, probe.agent_id)
            evidence["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            evidence["telemetry_after_id"] = after_id
            evidence["events"] = events
            diff = subprocess.run(
                ["git", "-C", str(workspace), "diff", "--binary", "HEAD", "--"],
                capture_output=True,
                text=True,
                check=False,
            )
            evidence["final_diff"] = diff.stdout if diff.returncode == 0 else None
            evidence["final_diff_error"] = diff.stderr if diff.returncode else None
            evidence["final_file_sha256"] = {
                name: sha256((workspace / name).read_bytes()).hexdigest()
                if (workspace / name).is_file() and not (workspace / name).is_symlink()
                else None
                for name in FIXTURE
            }
            capture_failed = cleanup_error or evidence.get("telemetry_read_error")
            if capture_failed and evidence["disposition"] == "pass":
                evidence.update(disposition="failed", stage="final_capture")
            evidence_path.write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n"
            )
            if capture_failed and evidence["stage"] == "final_capture":
                raise AssertionError(f"final evidence capture failed: {capture_failed}")
