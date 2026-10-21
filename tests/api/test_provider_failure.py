"""Provider failures through real SDK, stream and HTTP boundaries."""

import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from pydantic import BaseModel

from openminion import Agent, APIRuntime, ProviderError, tool
from openminion.api.queries.runs import list_runs
from openminion.api.server import dispatch_request
from openminion.base.config import OpenMinionConfig, save_config
from tests._csc_fixtures import _csc_install_default_agent


def _send_json(handler, status, payload):
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@contextmanager
def _local_provider_runtime(handler, provider_name, tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("TEST_PROVIDER_KEY", "local-dummy-key")
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider=provider_name)
    provider = getattr(config.providers, provider_name)
    provider.api_key_env = "TEST_PROVIDER_KEY"
    provider.base_url = f"http://127.0.0.1:{server.server_port}/v1"
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


@pytest.fixture(params=["openai", "anthropic"])
def rejected_provider(request, tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            _send_json(
                self,
                401,
                {
                    "error": {
                        "type": "authentication_error",
                        "message": "local fixture rejected credentials",
                    }
                },
            )

        def log_message(self, *_args):
            pass

    with _local_provider_runtime(
        Handler, request.param, tmp_path, monkeypatch
    ) as runtime:
        yield runtime


@pytest.fixture(params=["first_call", "after_tool", "duplicate_closure"])
def rate_limited_provider(request, tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            offered = [tool["function"]["name"] for tool in payload.get("tools", [])]
            limited = {
                "first_call": True,
                "after_tool": any(
                    message.get("role") == "tool" for message in payload["messages"]
                ),
                "duplicate_closure": not offered,
            }[request.param]
            if limited:
                _send_json(
                    self,
                    429,
                    {
                        "error": {
                            "type": "requests",
                            "code": "rate_limit_exceeded",
                            "message": "local fixture rate limit",
                        }
                    },
                )
                return
            message = {"role": "assistant", "content": "LOCAL_MARKER"}
            finish_reason = "stop"
            if "lookup_order" in offered:
                finish_reason = "tool_calls"
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "local-call",
                            "type": "function",
                            "function": {
                                "name": "lookup_order",
                                "arguments": json.dumps({"order_id": "A-104"}),
                            },
                        }
                    ],
                }
            _send_json(
                self,
                200,
                {
                    "id": "local-response",
                    "object": "chat.completion",
                    "model": "local",
                    "choices": [
                        {"index": 0, "message": message, "finish_reason": finish_reason}
                    ],
                    "usage": {
                        "prompt_tokens": 5,
                        "completion_tokens": 5,
                        "total_tokens": 10,
                    },
                },
            )

        def log_message(self, *_args):
            pass

    with _local_provider_runtime(Handler, "openai", tmp_path, monkeypatch) as runtime:
        yield runtime, request.param


class Answer(BaseModel):
    answer: str


@pytest.mark.parametrize("output_type", [str, Answer])
def test_agent_provider_failure_precedes_output_coercion(
    rejected_provider, output_type
):
    with Agent(runtime=rejected_provider, output_type=output_type) as agent:
        with pytest.raises(ProviderError) as raised:
            agent.run("hi", timeout_seconds=10)
        assert raised.value.code == "AUTH_ERROR"
        assert raised.value.details["status_code"] == 401
        assert raised.value.details["reason_code"] == "provider_auth_failed"
        runs = list_runs(None, session_id=agent.session_id, runtime=rejected_provider)[
            "runs"
        ]
    assert len(runs) == 1
    assert runs[0]["state"] == "failed"
    assert runs[0]["current_step"] == "turn.failed"


def test_agent_rate_limit_raises_typed_provider_error(rate_limited_provider):
    runtime, limited_call = rate_limited_provider
    calls = []

    @tool(min_scope="READ_ONLY")
    def lookup_order(order_id: str) -> str:
        """Return the status of one order."""
        calls.append(order_id)
        return f"order {order_id}: ready"

    # A repeated call reaches the duplicate-batch closure only without forcing.
    forced_tools = [] if limited_call == "duplicate_closure" else ["lookup_order"]
    with Agent(
        runtime=runtime, tools=[lookup_order], forced_tools=forced_tools
    ) as agent:
        with pytest.raises(ProviderError) as raised:
            agent.run("Check order A-104", timeout_seconds=30)
        runs = list_runs(None, session_id=agent.session_id, runtime=runtime)["runs"]
    assert raised.value.code == "RATE_LIMITED"
    assert raised.value.details["status_code"] == 429
    assert raised.value.details["reason_code"] == "provider_rate_limited"
    assert calls == ([] if limited_call == "first_call" else ["A-104"])
    assert len(runs) == 1
    assert runs[0]["state"] == "failed"
    assert runs[0]["current_step"] == "turn.failed"


def test_stream_provider_failure_uses_error_envelope(rejected_provider):
    handle = rejected_provider.submit_turn(
        payload={"message": "hi", "session_id": "stream-failure", "timeout_seconds": 10}
    )
    result = handle.result(timeout_s=15)
    chunks = list(handle.stream(timeout_s=1))
    assert len(result.errors) == 1
    assert result.errors[0].code == "turn_failed"
    assert "AUTH_ERROR" in result.errors[0].message
    assert result.final_text == ""
    assert chunks[-1].kind == "status"
    assert chunks[-1].data["status_key"] == "error"
    assert chunks[-1].data["terminal"] is True
    assert all(
        chunk.data["text"] == "" for chunk in chunks if chunk.kind == "final_text"
    )
    runs = list_runs(None, session_id="stream-failure", runtime=rejected_provider)[
        "runs"
    ]
    assert runs[0]["state"] == "failed"


def test_http_provider_failure_is_not_success(rejected_provider):
    status, payload = dispatch_request(
        "POST",
        "/turns",
        None,
        body={"message": "hi", "timeout_seconds": 10},
        runtime=rejected_provider,
    )
    assert int(status) >= 400
    assert payload["ok"] is False
    assert payload["error"]["code"] == "turn_failed"
    assert "AUTH_ERROR" in payload["error"]["message"]
