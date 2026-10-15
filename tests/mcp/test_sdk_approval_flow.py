from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

from openminion.base.config.mcp import MCPApprovalConfig, MCPServerConfig
from openminion.base.config.runtime import RuntimeConfig
from openminion.modules.brain.adapters.tool.runtime import ToolAdapter
from openminion.modules.tool.registry import ToolRegistry
from openminion.modules.tool.runtime.policy import Policy
from openminion.tools.mcp.manager import MCPFleetManager
from openminion.tools.mcp.plugin import build_mcp_tool_spec


FIXTURE_SERVER_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "mock_mcp_server.py"
)


@pytest.fixture
def sdk_mcp_tool(tmp_path: Path):
    server = MCPServerConfig(
        name="Fixture",
        transport="stdio",
        trusted=True,
        command=[sys.executable, str(FIXTURE_SERVER_PATH)],
        approval=MCPApprovalConfig(mode="always"),
    )
    manager = MCPFleetManager.from_runtime_config(RuntimeConfig(mcp_servers=[server]))
    try:
        listed = next(
            tool for tool in manager.discover_tools() if tool.remote_name == "echo-text"
        )
        spec = build_mcp_tool_spec(manager=manager, tool=listed)
        registry = ToolRegistry()
        registry.add(spec)
        adapter = ToolAdapter(
            workspace_root=tmp_path,
            runtime_registry=registry,
            policy=Policy(raw={"scope": "POWER_USER", "workspace_root": str(tmp_path)}),
        )
        yield manager, spec, adapter
    finally:
        manager.close()


def _execute(adapter: ToolAdapter, tool_name: str) -> dict:
    return adapter.execute(
        command={"tool_name": tool_name, "args": {"text": "hello"}},
        session_id="sdk-mcp-session",
        trace_id="sdk-mcp-trace",
    )


def test_sdk_mcp_callback_allow_executes_local_stdio_once(sdk_mcp_tool) -> None:
    manager, spec, adapter = sdk_mcp_tool
    adapter.set_approval_callback(lambda *_args: True)

    with mock.patch.object(manager, "call_tool", wraps=manager.call_tool) as call:
        result = _execute(adapter, spec.name)

    assert result["status"] == "success"
    assert result["outputs"]["content"] == "echo: hello"
    call.assert_called_once()


def test_sdk_mcp_callback_deny_does_not_execute_local_stdio(sdk_mcp_tool) -> None:
    manager, spec, adapter = sdk_mcp_tool
    adapter.set_approval_callback(lambda *_args: False)

    with mock.patch.object(manager, "call_tool", wraps=manager.call_tool) as call:
        result = _execute(adapter, spec.name)

    assert result["status"] == "error"
    assert result["error"]["code"] == "POLICY_DENIED"
    assert result["error"]["details"]["reason"] == "operator_denied"
    call.assert_not_called()


def test_sdk_mcp_callback_error_does_not_execute_local_stdio(sdk_mcp_tool) -> None:
    manager, spec, adapter = sdk_mcp_tool

    def fail(*_args) -> bool:
        raise RuntimeError("approval callback failed")

    adapter.set_approval_callback(fail)
    with mock.patch.object(manager, "call_tool", wraps=manager.call_tool) as call:
        result = _execute(adapter, spec.name)

    assert result["status"] == "error"
    assert result["error"]["code"] == "POLICY_DENIED"
    assert result["error"]["details"]["reason"] == "approval_callback_failed"
    call.assert_not_called()
