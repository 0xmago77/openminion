"""Internal runtime failures through the real SDK result path (#384)."""

import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace

import pytest

from openminion import Agent, APIRuntime, tool
from openminion.api.queries.runs import list_runs
from openminion.base.config import OpenMinionConfig, save_config
from openminion.services.gateway.turn.flow_models import _response_run_state
from tests._csc_fixtures import _csc_install_default_agent

FINAL_TEXT = "LOCAL_FINAL_ANSWER"


def _send_json(handler, status, payload):
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _completion(message, finish_reason):
    return {
        "id": "local-response",
        "object": "chat.completion",
        "model": "local",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
    }


def _tool_call(name, arguments):
    return _completion(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"local-{name}",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }
            ],
        },
        "tool_calls",
    )


class _ScriptedHandler(BaseHTTPRequestHandler):
    """Asks for `tool_name` once, then answers with FINAL_TEXT."""

    tool_name = ""

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        tool_choice = payload.get("tool_choice")
        forced = (
            tool_choice.get("function", {}).get("name")
            if isinstance(tool_choice, dict)
            else ""
        )
        if forced == "submit_output":
            schema = payload["tools"][0]["function"].get("parameters", {})
            arguments = (
                {"status": "final_answer", "reasoning": "answered"}
                if schema.get("title") == "FinalizationStatus"
                else {}
            )
            _send_json(self, 200, _tool_call("submit_output", arguments))
            return
        offered = {item["function"]["name"] for item in payload.get("tools", [])}
        tool_seen = any(m.get("role") == "tool" for m in payload["messages"])
        if self.tool_name in offered and not tool_seen:
            _send_json(self, 200, _tool_call(self.tool_name, {}))
            return
        _send_json(
            self, 200, _completion({"role": "assistant", "content": FINAL_TEXT}, "stop")
        )

    def log_message(self, *_args):
        pass


@contextmanager
def _scripted_runtime(tool_name, tmp_path, monkeypatch):
    handler = type("Handler", (_ScriptedHandler,), {"tool_name": tool_name})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("TEST_PROVIDER_KEY", "local-dummy-key")
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider="openai")
    config.providers.openai.api_key_env = "TEST_PROVIDER_KEY"
    config.providers.openai.base_url = f"http://127.0.0.1:{server.server_port}/v1"
    config.runtime.process_mode = "single-process"
    config.runtime.daemon_auto_start = False
    config.storage.path = str(tmp_path / "state.db")
    config_path = tmp_path / "agents.json"
    save_config(config, str(config_path))
    runtime = APIRuntime.from_config_path(
        str(config_path), home_root=tmp_path, data_root=tmp_path / "data"
    )
    try:
        yield runtime
    finally:
        runtime.close()
        server.shutdown()
        server.server_close()
        thread.join()


def _runs(agent, runtime):
    return list_runs(None, session_id=agent.session_id, runtime=runtime)["runs"]


class _NotJSON:
    pass


def test_internal_runtime_error_reports_failed_run(tmp_path, monkeypatch):
    @tool(idempotent=True, min_scope="READ_ONLY")
    def bad_return() -> str:
        """Return an object that cannot be JSON-serialized."""
        return _NotJSON()  # type: ignore[return-value]

    with _scripted_runtime("bad_return", tmp_path, monkeypatch) as runtime:
        with Agent(runtime=runtime, tools=[bad_return]) as agent:
            result = agent.run("call the tool", timeout_seconds=30)
            runs = _runs(agent, runtime)

    assert result.run_state == "failed"
    assert result.raw["run_state"] == "failed"
    assert result.metadata["error_code"] == "RUNTIME_ERROR"
    assert "not JSON serializable" in result.metadata["error_message"]
    assert result.metadata["brain_working_status"] == "error"
    assert len(runs) == 1
    assert runs[0]["state"] == "failed"
    assert runs[0]["current_step"] == "turn.failed"


def test_successful_turn_still_completes(tmp_path, monkeypatch):
    @tool(idempotent=True, min_scope="READ_ONLY")
    def good_return() -> str:
        """Return a plain string."""
        return "fine"

    with _scripted_runtime("good_return", tmp_path, monkeypatch) as runtime:
        with Agent(runtime=runtime, tools=[good_return]) as agent:
            result = agent.run("call the tool", timeout_seconds=30)
            runs = _runs(agent, runtime)

    assert result.run_state == "completed"
    assert FINAL_TEXT in result.text
    assert "error_code" not in result.metadata
    assert len(runs) == 1
    assert runs[0]["state"] == "completed"
    assert runs[0]["current_step"] == "turn.completed"


def test_recoverable_tool_error_followed_by_answer_completes(tmp_path, monkeypatch):
    calls = []

    @tool(idempotent=True, min_scope="READ_ONLY")
    def flaky() -> str:
        """Raise inside the tool."""
        calls.append(1)
        raise RuntimeError("tool exploded")

    with _scripted_runtime("flaky", tmp_path, monkeypatch) as runtime:
        with Agent(runtime=runtime, tools=[flaky]) as agent:
            result = agent.run("call the tool", timeout_seconds=30)
            runs = _runs(agent, runtime)

    assert calls == [1]
    assert result.run_state == "completed"
    assert FINAL_TEXT in result.text
    assert result.stats.get("tool_errors") == 1
    assert result.metadata["brain_working_status"] != "error"
    assert len(runs) == 1
    assert runs[0]["state"] == "completed"


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ({"brain_status": "error", "brain_working_status": "error"}, "failed"),
        # A tool failure answered with an error-status reply keeps the brain
        # working state active; it is not a terminal runtime failure.
        ({"brain_status": "error", "brain_working_status": "active"}, "completed"),
        ({"brain_status": "error"}, "completed"),
        ({"brain_status": "done", "brain_working_status": "done"}, "completed"),
        ({}, "completed"),
    ],
)
def test_response_run_state_uses_brain_state_machine_verdict(metadata, expected):
    assert _response_run_state(SimpleNamespace(metadata=metadata)) == expected
