from __future__ import annotations

import json

import pytest

from openminion.base.config.mcp import MCPServerConfig
from openminion.tools.mcp.manager import MCPProtocolError, MCPServerSession
from openminion.tools.mcp.results import (
    normalize_completion_result,
    normalize_prompt_result,
    normalize_resource_result,
    normalize_tool_result,
)


class _ToolListTransport:
    def __init__(self) -> None:
        self.notifications: list[tuple[str, dict]] = []

    @property
    def authorization_identity(self) -> str:
        return ""

    def stderr_tail(self, *, limit: int = 4096, wait_seconds: float = 0.0) -> str:
        del limit, wait_seconds
        return ""

    def is_running(self) -> bool:
        return True

    def start(self) -> None:
        return None

    def notify(self, method: str, params: dict | None = None) -> None:
        self.notifications.append((method, dict(params or {})))

    def close(self) -> None:
        return None

    def request(
        self,
        *,
        method: str,
        params: dict | None = None,
        timeout_seconds: float,
        server_request_handler=None,
    ) -> dict:
        del params, timeout_seconds, server_request_handler
        if method == "server/discover":
            raise MCPProtocolError("method not found", details={"code": -32601})
        if method == "initialize":
            return {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
            }
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "rich-tool",
                        "description": "rich result fixture",
                        "inputSchema": {"type": "object", "properties": {}},
                        "outputSchema": {
                            "type": "object",
                            "properties": {"status": {"type": "string"}},
                            "required": ["status"],
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        return {}


def _session() -> MCPServerSession:
    return MCPServerSession(
        MCPServerConfig(name="Fixture", command=["python", "-m", "fixture"])
    )


def test_mcp_tool_discovery_preserves_output_schema() -> None:
    session = _session()
    session._transport = _ToolListTransport()  # noqa: SLF001

    tools = session.list_tools()

    assert tools[0].output_schema == {
        "type": "object",
        "properties": {"status": {"type": "string"}},
        "required": ["status"],
        "additionalProperties": False,
    }


def test_mcp_tool_result_preserves_rich_content_and_validates_structured_content() -> (
    None
):
    session = _session()
    session._output_schemas_by_tool["rich-tool"] = {  # noqa: SLF001
        "type": "object",
        "properties": {"status": {"type": "string"}},
        "required": ["status"],
        "additionalProperties": False,
    }

    normalized = normalize_tool_result(
        server_name=session.server_name,
        remote_name="rich-tool",
        result={
            "content": [
                {"type": "text", "text": "done"},
                {"type": "image", "mimeType": "image/png", "data": "abc123"},
                {"type": "audio", "mimeType": "audio/wav", "data": "def456"},
                {"type": "resource_link", "uri": "file://fixture/readme.md"},
            ],
            "structuredContent": {"status": "ok"},
            "isError": False,
        },
        output_schema=session._output_schemas_by_tool["rich-tool"],  # noqa: SLF001
        stderr_tail="",
    )

    assert normalized["content"] == "done"
    assert normalized["data"]["mcp_server"] == session.server_name
    assert normalized["data"]["mcp_remote_tool_name"] == "rich-tool"
    assert normalized["data"]["structured_content"] == {"status": "ok"}
    assert normalized["data"]["output_schema"]["required"] == ["status"]
    content_items = normalized["data"]["content_items"]
    assert [item["type"] for item in content_items] == [
        "text",
        "image",
        "audio",
        "resource_link",
    ]
    assert content_items[1]["mimeType"] == "image/png"
    assert content_items[2]["mimeType"] == "audio/wav"
    assert content_items[3]["uri"] == "file://fixture/readme.md"


def test_mcp_tool_result_rejects_invalid_structured_content() -> None:
    session = _session()
    session._output_schemas_by_tool["rich-tool"] = {  # noqa: SLF001
        "type": "object",
        "properties": {"status": {"type": "string"}},
        "required": ["status"],
        "additionalProperties": False,
    }

    with pytest.raises(MCPProtocolError) as excinfo:
        normalize_tool_result(
            server_name=session.server_name,
            remote_name="rich-tool",
            result={
                "content": [{"type": "text", "text": "bad"}],
                "structuredContent": {"status": 123},
                "isError": False,
            },
            output_schema=session._output_schemas_by_tool["rich-tool"],  # noqa: SLF001
            stderr_tail="",
        )

    assert excinfo.value.reason_code == "mcp_output_schema_invalid"


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"type": "object"}, {"status": "ok"}),
        ({"type": "array"}, ["ok", 2]),
        ({"type": "string"}, "ok"),
        ({"type": "number"}, 2.5),
        ({"type": "boolean"}, True),
        ({"type": "null"}, None),
    ],
)
def test_mcp_tool_result_accepts_all_structured_json_types(
    schema: dict,
    value,
) -> None:
    normalized = normalize_tool_result(
        server_name="fixture",
        remote_name="rich-tool",
        result={"content": [], "structuredContent": value, "isError": False},
        output_schema=schema,
        stderr_tail="",
    )

    assert normalized["data"]["structured_content"] == value
    assert normalized["data"]["structured_content_present"] is True
    assert normalized["content"] == json.dumps(value, sort_keys=True)


def test_mcp_tool_result_distinguishes_absent_structured_content_from_null() -> None:
    absent = normalize_tool_result(
        server_name="fixture",
        remote_name="rich-tool",
        result={"content": [], "isError": False},
        output_schema={"type": "null"},
        stderr_tail="",
    )
    explicit_null = normalize_tool_result(
        server_name="fixture",
        remote_name="rich-tool",
        result={"content": [], "structuredContent": None, "isError": False},
        output_schema={"type": "null"},
        stderr_tail="",
    )

    assert absent["data"]["structured_content_present"] is False
    assert absent["content"] == ""
    assert explicit_null["data"]["structured_content_present"] is True
    assert explicit_null["content"] == "null"


def test_mcp_tool_result_validates_explicit_null_against_output_schema() -> None:
    with pytest.raises(MCPProtocolError) as excinfo:
        normalize_tool_result(
            server_name="fixture",
            remote_name="rich-tool",
            result={"content": [], "structuredContent": None, "isError": False},
            output_schema={"type": "string"},
            stderr_tail="",
        )

    assert excinfo.value.reason_code == "mcp_output_schema_invalid"


@pytest.mark.parametrize(
    ("normalizer", "result"),
    [
        (normalize_completion_result, {"completion": {"values": "bad"}}),
        (normalize_completion_result, {"completion": {"total": "1"}}),
        (normalize_completion_result, {"completion": {"hasMore": "false"}}),
    ],
)
def test_completion_result_rejects_invalid_payload_types(normalizer, result) -> None:
    with pytest.raises(MCPProtocolError) as excinfo:
        normalizer(result)

    assert excinfo.value.reason_code == "mcp_result_shape_invalid"


@pytest.mark.parametrize(
    ("normalizer", "kwargs"),
    [
        (
            normalize_tool_result,
            {
                "server_name": "fixture",
                "remote_name": "tool",
                "result": {"content": ["bad"]},
                "output_schema": {},
                "stderr_tail": "",
            },
        ),
        (
            normalize_tool_result,
            {
                "server_name": "fixture",
                "remote_name": "tool",
                "result": {"isError": "false"},
                "output_schema": {},
                "stderr_tail": "",
            },
        ),
        (
            normalize_prompt_result,
            {
                "server_name": "fixture",
                "remote_name": "prompt",
                "result": {"messages": {}},
            },
        ),
        (
            normalize_resource_result,
            {
                "server_name": "fixture",
                "resource_uri": "file://fixture",
                "result": {"contents": ["bad"]},
            },
        ),
    ],
)
def test_mcp_results_reject_invalid_object_lists(normalizer, kwargs) -> None:
    with pytest.raises(MCPProtocolError) as excinfo:
        normalizer(**kwargs)

    assert excinfo.value.reason_code == "mcp_result_shape_invalid"


@pytest.mark.parametrize(
    ("normalizer", "kwargs"),
    [
        (normalize_completion_result, {"result": {"completion": {}}}),
        (
            normalize_tool_result,
            {
                "server_name": "fixture",
                "remote_name": "tool",
                "result": {},
                "output_schema": {},
                "stderr_tail": "",
            },
        ),
        (
            normalize_prompt_result,
            {"server_name": "fixture", "remote_name": "prompt", "result": {}},
        ),
        (
            normalize_resource_result,
            {"server_name": "fixture", "resource_uri": "file://fixture", "result": {}},
        ),
    ],
)
def test_mcp_results_require_protocol_result_fields(normalizer, kwargs) -> None:
    with pytest.raises(MCPProtocolError) as excinfo:
        normalizer(**kwargs)

    assert excinfo.value.reason_code == "mcp_result_shape_invalid"


@pytest.mark.parametrize(
    ("normalizer", "kwargs"),
    [
        (
            normalize_tool_result,
            {
                "server_name": "fixture",
                "remote_name": "tool",
                "result": {"content": [{}]},
                "output_schema": {},
                "stderr_tail": "",
            },
        ),
        (
            normalize_prompt_result,
            {
                "server_name": "fixture",
                "remote_name": "prompt",
                "result": {"messages": [{}]},
            },
        ),
        (
            normalize_resource_result,
            {
                "server_name": "fixture",
                "resource_uri": "file://fixture",
                "result": {"contents": [{}]},
            },
        ),
    ],
)
def test_mcp_results_reject_empty_result_items(normalizer, kwargs) -> None:
    with pytest.raises(MCPProtocolError) as excinfo:
        normalizer(**kwargs)

    assert excinfo.value.reason_code == "mcp_result_shape_invalid"
