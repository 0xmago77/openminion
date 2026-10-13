import time
from types import SimpleNamespace

import pytest

from openminion.modules.brain.adapters.tool.results import run_tool_spec
from openminion.modules.brain.execution.validation import normalize_execution_result
from openminion.modules.brain.adapters.tool.results import _derive_toolspec_summary


def test_failed_tool_prefers_diagnostic_summary() -> None:
    payload = {
        "status": "error",
        "summary": (
            "Command exited with code 255.\n\nstderr:\n"
            "deploy@example: Permission denied (publickey,password)."
        ),
        "error": {
            "code": "EXEC_ERROR",
            "message": "command exited with code 255",
        },
    }

    summary = _derive_toolspec_summary(
        payload,
        status="error",
        tool_name="exec.run",
    )

    assert "Permission denied" in summary


def test_failed_tool_uses_error_when_summary_is_absent() -> None:
    payload = {
        "status": "error",
        "error": {
            "code": "EXEC_ERROR",
            "message": "command exited with code 255",
        },
    }

    summary = _derive_toolspec_summary(
        payload,
        status="error",
        tool_name="exec.run",
    )

    assert summary == "command exited with code 255"


@pytest.mark.parametrize(
    "value",
    [
        "order A-104: ready",
        "",
        0,
        False,
        None,
        [1, "two"],
        "x" * 1200,
        {"answer": "ready"},
    ],
)
def test_tool_values_survive_action_result_normalization(monkeypatch, value):
    events = []
    monkeypatch.setattr(
        "openminion.modules.brain.adapters.tool.results.emit_tool_execution_event",
        lambda **event: events.append(event),
    )
    spec = SimpleNamespace(name="lookup_order", handler=lambda _args, _ctx: value)
    raw = run_tool_spec(
        spec=spec,
        validated_args={},
        context=SimpleNamespace(tool_call_id="call-1", artifacts=[]),
        start_time=time.monotonic(),
        background_write_authorized=False,
        tool_name=spec.name,
    )
    result, job = normalize_execution_result(
        command_id="call-1", raw=raw, provider="tool", tool_name=spec.name
    )
    assert result.outputs == (value if isinstance(value, dict) else {"data": value})
    assert result.status == "success"
    assert result.error is None
    assert job is None
    assert [event["event_type"] for event in events] == [
        "tool.execution.started",
        "tool.execution.completed",
    ]
