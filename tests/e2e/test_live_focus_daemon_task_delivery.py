from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import sqlite3
import time

import pytest

from openminion.cli.commands.daemon import daemon_start, daemon_stop
from openminion.modules.task.constants import DEFAULT_INTEGRATED_SQLITE_SUBPATH
from tests.e2e.cli.focus.harness import FocusProbe
from tests.e2e.cli.focus.harness.scenarios import FocusScenario
from tests.e2e.test_live_cli_chat_minimax_official_task_cron import (
    _trace_proves_tool_execution,
)
from tests.helpers.live_cli_chat_alibaba import framework_root, require_live_flag
from tests.helpers.live_e2e_profiles import resolve_live_config_path

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(900)]

_AGENT_ID = "minimax-m2-7"
_CONFIG = resolve_live_config_path(
    "per-agent-minimax-official.json",
    framework_root(),
)


def _isolated_config(run_root: Path) -> Path:
    payload = json.loads(_CONFIG.read_text(encoding="utf-8"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        payload.setdefault("runtime", {})["ipc_port"] = listener.getsockname()[1]
    payload["runtime"]["tool_workspace_root"] = str(run_root)
    path = run_root / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def _rows(db_path: Path, query: str, params: tuple[object, ...] = ()) -> list[dict]:
    if not db_path.exists():
        return []
    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def _wait_for_finished_run(db_path: Path, job_id: str) -> dict:
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        runs = _rows(
            db_path,
            "SELECT * FROM cron_runs WHERE job_id = ? ORDER BY created_at DESC",
            (job_id,),
        )
        if runs and runs[0]["state"] in {
            "finished",
            "failed",
            "cancelled",
            "timed_out",
        }:
            return runs[0]
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for cron run for {job_id}")


def _wait_for_finished_run_count(
    db_path: Path,
    job_id: str,
    expected: int,
) -> list[dict]:
    deadline = time.monotonic() + 180
    terminal = {"finished", "failed", "cancelled", "timed_out"}
    while time.monotonic() < deadline:
        runs = _rows(
            db_path,
            "SELECT * FROM cron_runs WHERE job_id = ? ORDER BY created_at",
            (job_id,),
        )
        if len(runs) >= expected and all(row["state"] in terminal for row in runs):
            return runs
        time.sleep(0.5)
    raise AssertionError(
        f"timed out waiting for {expected} finished cron runs for {job_id}"
    )


def _cron_announcements(
    runtime_db_path: Path,
    *,
    session_id: str,
    conversation_id: str,
) -> tuple[list[dict], list[dict]]:
    outbound = _rows(
        runtime_db_path,
        "SELECT * FROM messages WHERE session_id = ? AND role = 'outbound' "
        "AND conversation_id = ?",
        (session_id, conversation_id),
    )
    messages = [
        row
        for row in outbound
        if json.loads(row["metadata_json"]).get("cron_announce") == "true"
    ]
    events = _rows(
        runtime_db_path,
        "SELECT * FROM events WHERE session_id = ? AND event_type = 'cron.announce'",
        (session_id,),
    )
    return messages, events


def _trace_proves_file_read(
    trace_root: Path,
    *,
    session_id: str,
    relative_path: str,
) -> bool:
    expected_file = (trace_root.parent / relative_path).resolve()

    def matching_call(node: object, *, within_arguments: bool = False) -> bool:
        if isinstance(node, dict):
            calls = None if within_arguments else node.get("tool_calls")
            if isinstance(calls, list):
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    function = call.get("function")
                    if call.get("name") == "file.read":
                        arguments = call.get("arguments")
                    elif (
                        isinstance(function, dict)
                        and function.get("name") == "file.read"
                    ):
                        arguments = function.get("arguments")
                    else:
                        continue
                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except json.JSONDecodeError:
                            continue
                    if isinstance(arguments, dict):
                        observed = str(arguments.get("path") or "").strip()
                        if observed == relative_path:
                            return True
                        observed_path = Path(observed)
                        if (
                            observed_path.is_absolute()
                            and observed_path.resolve() == expected_file
                        ):
                            return True
            return any(
                matching_call(
                    value, within_arguments=within_arguments or key == "arguments"
                )
                for key, value in node.items()
            )
        if isinstance(node, list):
            return any(
                matching_call(item, within_arguments=within_arguments) for item in node
            )
        return False

    for trace_path in trace_root.rglob("*.json"):
        try:
            payload = json.loads(trace_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        trace = payload.get("trace") if isinstance(payload, dict) else None
        if not isinstance(trace, dict):
            continue
        trace_session_id = str(trace.get("session_id") or "")
        if trace_session_id != session_id and not trace_session_id.startswith(
            f"{session_id}::"
        ):
            continue
        if matching_call(payload):
            return True
    return False


def test_trace_file_read_matches_exact_workspace_file_identity(tmp_path: Path) -> None:
    trace_root = tmp_path / "traces"
    trace_root.mkdir()
    trace_path = trace_root / "trace.json"

    def write_trace(path: str) -> None:
        trace_path.write_text(
            json.dumps(
                {
                    "trace": {"session_id": "watch:1::conv:1"},
                    "response": {
                        "tool_calls": [
                            {
                                "name": "file.read",
                                "arguments": {"path": path},
                            }
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )

    write_trace("release-status.json")
    assert _trace_proves_file_read(
        trace_root,
        session_id="watch:1",
        relative_path="release-status.json",
    )

    write_trace(str(tmp_path / "release-status.json"))
    assert _trace_proves_file_read(
        trace_root,
        session_id="watch:1",
        relative_path="release-status.json",
    )

    write_trace(str(tmp_path / "other.json"))
    assert not _trace_proves_file_read(
        trace_root,
        session_id="watch:1",
        relative_path="release-status.json",
    )


@pytest.mark.skipif(not _CONFIG.exists(), reason=f"missing live config: {_CONFIG}")
def test_official_minimax_focus_daemon_preserves_conversation_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_live_flag()
    openminion_root = Path(__file__).resolve().parents[2]
    python_bin = Path(
        os.getenv("OPENMINION_PYTHON", openminion_root / ".venv/bin/python3.11")
    )
    run_root = tmp_path / "focus-daemon-task"
    data_root = run_root / "data"
    trace_root = run_root / "traces"
    data_root.mkdir(parents=True)
    trace_root.mkdir(parents=True)
    config_path = _isolated_config(run_root)
    session_id = "tlp-focus-daemon-origin"
    conversation_id = f"focus-{session_id}"
    home_root = run_root / "home"
    probe = FocusProbe(
        python_bin=python_bin,
        openminion_root=openminion_root,
        framework_root=framework_root(),
        data_root=data_root,
        config_path=config_path,
        agent_id=_AGENT_ID,
        workdir=openminion_root,
        session_id=session_id,
        include_project_context=False,
        allow_unsandboxed_exec=False,
    )
    monkeypatch.setenv("OPENMINION_TRACE_REQUESTS", "1")
    monkeypatch.setenv("OPENMINION_TRACE_REQUESTS_DIR", str(trace_root))
    due_at = datetime.now(timezone.utc) + timedelta(seconds=90)
    task_name = "tlp-focus-daemon-conversation-delivery"

    assert daemon_start(str(config_path), home_root=home_root, data_root=data_root) == 0
    try:
        with probe.session(rows=52, cols=180) as session:
            probe.wait_ready(session)
            probe.run_turn(
                session,
                FocusScenario(
                    scenario_id="tlp-focus-daemon-delivery",
                    prompt=(
                        "Use task.schedule to create a one-time task at exactly "
                        f"{due_at.isoformat()}. Set name to {task_name!r}, instruction "
                        "to 'Reply with exactly: TLP_DELIVERED', and report the exact "
                        "task_id."
                    ),
                    expected_markers=(),
                    requires_approval=True,
                    max_auto_approvals=3,
                    approval_reply="session",
                    timeout=240,
                ),
            )

        db_path = data_root / "state" / "brain" / "sessions.db"
        jobs = _rows(
            db_path,
            "SELECT * FROM cron_jobs WHERE name = ?",
            (task_name,),
        )
        assert len(jobs) == 1
        job = jobs[0]
        payload = json.loads(job["payload_json"])
        origin = payload["_openminion_origin"]
        assert origin["session_id"] == session_id
        assert origin["conversation_id"] == conversation_id
        assert _trace_proves_tool_execution(trace_root, "task.schedule")

        run = _wait_for_finished_run(db_path, job["job_id"])
        runs = _rows(
            db_path,
            "SELECT * FROM cron_runs WHERE job_id = ?",
            (job["job_id"],),
        )
        assert [row["run_id"] for row in runs] == [run["run_id"]]
        assert run["state"] == "finished"
        assert run["error_json"] is None
        assert run["isolated_session_id"]
        assert json.loads(run["delivery_targets_json"]) == ["announce:last"]
        delivery = json.loads(run["output_json"])["delivery"]
        assert delivery == {
            "mode": "announce",
            "state": "succeeded",
            "targets": ["announce:last"],
        }
        completed_task = _rows(
            data_root / DEFAULT_INTEGRATED_SQLITE_SUBPATH,
            "SELECT state FROM scheduled_tasks WHERE cron_job_id = ?",
            (job["job_id"],),
        )
        assert completed_task == [{"state": "done"}]
        completed_job = _rows(
            db_path,
            "SELECT enabled FROM cron_jobs WHERE job_id = ?",
            (job["job_id"],),
        )
        assert completed_job == [{"enabled": 0}]

        runtime_db_path = data_root / "state" / "openminion.db"
        outbound = _rows(
            runtime_db_path,
            "SELECT * FROM messages WHERE session_id = ? AND role = 'outbound' "
            "AND conversation_id = ?",
            (session_id, conversation_id),
        )
        cron_delivery = [
            row
            for row in outbound
            if json.loads(row["metadata_json"]).get("cron_announce") == "true"
        ]
        assert len(cron_delivery) == 1
        assert "TLP_DELIVERED" in cron_delivery[0]["body"]
        events = _rows(
            runtime_db_path,
            "SELECT * FROM events WHERE session_id = ? "
            "AND event_type = 'cron.announce'",
            (session_id,),
        )
        assert len(events) == 1
        event_payload = json.loads(events[0]["payload_json"])
        assert event_payload["conversation_id"] == conversation_id
        assert event_payload["cron_run_id"] == run["run_id"]
    finally:
        daemon_stop(str(config_path), home_root=home_root, data_root=data_root)


@pytest.mark.skipif(not _CONFIG.exists(), reason=f"missing live config: {_CONFIG}")
def test_official_minimax_focus_daemon_material_change_watch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_live_flag()
    openminion_root = Path(__file__).resolve().parents[2]
    python_bin = Path(
        os.getenv("OPENMINION_PYTHON", openminion_root / ".venv/bin/python3.11")
    )
    run_root = tmp_path / "focus-daemon-watch"
    data_root = run_root / "data"
    trace_root = run_root / "traces"
    data_root.mkdir(parents=True)
    trace_root.mkdir(parents=True)
    fixture_path = run_root / "release-status.json"
    fixture_path.write_text(
        json.dumps({"release": "cedar", "status": "ready", "checked_at": "t0"}),
        encoding="utf-8",
    )
    config_path = _isolated_config(run_root)
    session_id = "twmc-focus-daemon-origin"
    conversation_id = f"focus-{session_id}"
    home_root = run_root / "home"
    probe = FocusProbe(
        python_bin=python_bin,
        openminion_root=openminion_root,
        framework_root=framework_root(),
        data_root=data_root,
        config_path=config_path,
        agent_id=_AGENT_ID,
        workdir=run_root,
        session_id=session_id,
        include_project_context=False,
        allow_unsandboxed_exec=False,
    )
    monkeypatch.setenv("OPENMINION_TRACE_REQUESTS", "1")
    monkeypatch.setenv("OPENMINION_TRACE_REQUESTS_DIR", str(trace_root))
    watch_name = "twmc-release-status-material-change"
    daemon_running = False

    assert daemon_start(str(config_path), home_root=home_root, data_root=data_root) == 0
    daemon_running = True
    try:
        with probe.session(rows=58, cols=180) as session:
            probe.wait_ready(session)
            probe.run_turn(
                session,
                FocusScenario(
                    scenario_id="twmc-focus-daemon-material-change",
                    prompt=(
                        "Use task.watch to create a watch named by description "
                        f"{watch_name!r}. Every 1 minute, read release-status.json "
                        "from the current workspace. The alert condition is exactly "
                        "that the JSON field status is not 'ready'; changes to "
                        "checked_at alone are not material. Use at most 4 checks, "
                        "a 10 minute TTL, a 60 second check timeout, delivery "
                        "'announce', and stop_on_condition true. Do not configure an "
                        "action and do not authorize writes. Report the exact task_id."
                    ),
                    expected_markers=(),
                    requires_approval=True,
                    max_auto_approvals=3,
                    approval_reply="session",
                    timeout=240,
                ),
            )

        db_path = data_root / "state" / "brain" / "sessions.db"
        jobs = _rows(
            db_path,
            "SELECT * FROM cron_jobs WHERE name = ?",
            (watch_name,),
        )
        assert len(jobs) == 1
        job = jobs[0]
        job_id = str(job["job_id"])
        payload = json.loads(job["payload_json"])
        watch = payload["_openminion_watch"]
        assert watch["interval_minutes"] == 1
        assert watch["max_checks"] == 4
        assert watch["ttl_minutes"] == 10
        assert watch["timeout_seconds"] == 60
        assert watch["stop_on_condition"] is True
        assert watch["on_condition_action"] is None
        assert watch["write_authorized"] is False
        assert payload["_openminion_origin"]["session_id"] == session_id
        assert _trace_proves_tool_execution(trace_root, "task.watch")

        runtime_db_path = data_root / "state" / "openminion.db"
        first_two = _wait_for_finished_run_count(db_path, job_id, 1)
        first_output = json.loads(first_two[0]["output_json"])
        assert first_two[0]["state"] == "finished"
        assert first_output["watch_condition_valid"] is True
        assert first_output["watch_condition_met"] is False
        assert first_output["watch_delivery_requested"] is False
        assert _trace_proves_file_read(
            trace_root,
            session_id=str(first_two[0]["isolated_session_id"]),
            relative_path="release-status.json",
        )
        assert _cron_announcements(
            runtime_db_path,
            session_id=session_id,
            conversation_id=conversation_id,
        ) == ([], [])

        fixture_path.write_text(
            json.dumps({"release": "cedar", "status": "ready", "checked_at": "t1"}),
            encoding="utf-8",
        )
        first_two = _wait_for_finished_run_count(db_path, job_id, 2)
        second_output = json.loads(first_two[1]["output_json"])
        assert second_output["watch_condition_valid"] is True
        assert second_output["watch_condition_met"] is False
        assert second_output["watch_delivery_requested"] is False
        assert _trace_proves_file_read(
            trace_root,
            session_id=str(first_two[1]["isolated_session_id"]),
            relative_path="release-status.json",
        )
        assert _cron_announcements(
            runtime_db_path,
            session_id=session_id,
            conversation_id=conversation_id,
        ) == ([], [])

        assert (
            daemon_stop(str(config_path), home_root=home_root, data_root=data_root) == 0
        )
        daemon_running = False
        before_restart = _rows(
            db_path,
            "SELECT job_id FROM cron_jobs WHERE name = ?",
            (watch_name,),
        )
        assert before_restart == [{"job_id": job_id}]
        fixture_path.write_text(
            json.dumps({"release": "cedar", "status": "blocked", "checked_at": "t2"}),
            encoding="utf-8",
        )
        assert (
            daemon_start(str(config_path), home_root=home_root, data_root=data_root)
            == 0
        )
        daemon_running = True

        runs = _wait_for_finished_run_count(db_path, job_id, 3)
        third_output = json.loads(runs[2]["output_json"])
        assert third_output["watch_condition_valid"] is True
        assert third_output["watch_condition_met"] is True
        assert third_output["watch_delivery_requested"] is True
        assert third_output["watch_terminal"] is True
        assert third_output["watch_terminal_reason"] == "condition_met"
        assert _trace_proves_file_read(
            trace_root,
            session_id=str(runs[2]["isolated_session_id"]),
            relative_path="release-status.json",
        )

        completed_task = _rows(
            data_root / DEFAULT_INTEGRATED_SQLITE_SUBPATH,
            "SELECT state, cron_job_id FROM scheduled_tasks WHERE cron_job_id = ?",
            (job_id,),
        )
        assert completed_task == [{"state": "done", "cron_job_id": job_id}]
        completed_job = _rows(
            db_path,
            "SELECT enabled, payload_json FROM cron_jobs WHERE job_id = ?",
            (job_id,),
        )
        assert len(completed_job) == 1
        assert completed_job[0]["enabled"] == 0
        final_watch = json.loads(completed_job[0]["payload_json"])["_openminion_watch"]
        assert final_watch["checks_completed"] == 3
        assert final_watch["last_condition_met"] is True
        assert final_watch["last_terminal_reason"] == "condition_met"

        messages, events = _cron_announcements(
            runtime_db_path,
            session_id=session_id,
            conversation_id=conversation_id,
        )
        assert len(messages) == 1
        assert len(events) == 1
        assert (
            json.loads(messages[0]["metadata_json"])["cron_run_id"] == runs[2]["run_id"]
        )
        assert json.loads(events[0]["payload_json"])["cron_run_id"] == runs[2]["run_id"]

        time.sleep(65)
        assert (
            len(
                _rows(
                    db_path, "SELECT run_id FROM cron_runs WHERE job_id = ?", (job_id,)
                )
            )
            == 3
        )
        final_messages, final_events = _cron_announcements(
            runtime_db_path,
            session_id=session_id,
            conversation_id=conversation_id,
        )
        assert len(final_messages) == 1
        assert len(final_events) == 1
    finally:
        if daemon_running:
            daemon_stop(str(config_path), home_root=home_root, data_root=data_root)
