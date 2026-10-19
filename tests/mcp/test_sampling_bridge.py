from __future__ import annotations

import sys
from pathlib import Path

import pytest

from openminion.base.config.mcp import MCPServerConfig
from openminion.base.config.runtime import RuntimeConfig
from openminion.modules.llm.providers.base import ProviderRequest, ProviderResponse
from openminion.tools.mcp.errors import MCPProtocolError
from openminion.tools.mcp.manager import MCPFleetManager
from openminion.tools.mcp.sampling import OpenMinionSamplingHandler
from openminion.tools.mcp.schemas import MCPSamplingMessage, MCPSamplingRequest


FIXTURE_SERVER_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "mock_mcp_server.py"
)


def _runtime_config(*, sampling_mode: str) -> RuntimeConfig:
    return RuntimeConfig(
        mcp_sampling_mode=sampling_mode,
        mcp_servers=[
            MCPServerConfig(
                name="Fixture",
                transport="stdio",
                trusted=True,
                command=[sys.executable, str(FIXTURE_SERVER_PATH)],
                env={
                    "MOCK_MCP_ENABLE_CLIENT_REQUEST_TOOLS": "1",
                    "MOCK_MCP_REQUIRE_CLIENT_CAPABILITIES": "sampling",
                },
                request_timeout_seconds=5.0,
                startup_timeout_seconds=5.0,
            )
        ],
    )


def test_sampling_bridge_denies_when_policy_mode_is_deny() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config(sampling_mode="deny"))
    try:
        declared = manager.client_capability_state.declared_capabilities()
        assert declared["sampling"] == {}
        assert any(
            tool.remote_name == "request-sampling" for tool in manager.discover_tools()
        )

        result = manager.call_tool(
            server_name="fixture",
            remote_name="request-sampling",
            arguments={},
        )

        assert result["ok"] is True
        assert result["content"].startswith("sampling: Sampling denied")
        events = manager.mcp_sampling_events()
        assert events[-1]["allowed"] is False
        assert events[-1]["stop_reason"] == "denied"
    finally:
        manager.close()


def test_sampling_bridge_invokes_bound_openminion_provider_executor() -> None:
    captured: list[ProviderRequest] = []

    def _executor(request: ProviderRequest) -> ProviderResponse:
        captured.append(request)
        return ProviderResponse(
            text="hello from real provider path",
            model="fake-provider",
            finish_reason="endTurn",
        )

    manager = MCPFleetManager.from_runtime_config(
        _runtime_config(sampling_mode="allow")
    )
    manager.bind_sampling_executor(_executor)
    try:
        assert any(
            tool.remote_name == "request-sampling" for tool in manager.discover_tools()
        )

        result = manager.call_tool(
            server_name="fixture",
            remote_name="request-sampling",
            arguments={},
        )

        assert result["ok"] is True
        assert result["content"] == "sampling: hello from real provider path"
        assert captured
        assert captured[0].metadata["origin"] == "mcp.sampling"
        assert captured[0].metadata["mcp_server"] == "fixture"
        assert "Say hello from sampling." in captured[0].user_message
        assert captured[0].max_output_tokens == 32
        events = manager.mcp_sampling_events()
        assert events[-1]["allowed"] is True
        assert events[-1]["model"] == "fake-provider"
    finally:
        manager.close()


def test_sampling_bridge_preserves_prior_transcript() -> None:
    captured: list[ProviderRequest] = []
    handler = OpenMinionSamplingHandler(mode="allow")
    handler.bind_executor(
        lambda request: (
            captured.append(request) or ProviderResponse(text="ok", model="fixture")
        )
    )

    handler.sample(
        server_name="fixture",
        request=MCPSamplingRequest(
            messages=(
                MCPSamplingMessage(role="user", content="first question"),
                MCPSamplingMessage(role="assistant", content="first answer"),
                MCPSamplingMessage(role="user", content="follow-up"),
            ),
            max_tokens=64,
        ),
    )

    assert captured[0].user_message == "follow-up"
    assert [(item.role, item.content) for item in captured[0].history] == [
        ("user", "first question"),
        ("assistant", "first answer"),
    ]
    assert captured[0].max_output_tokens == 64


def test_sampling_bridge_rejects_transcript_without_user_message() -> None:
    handler = OpenMinionSamplingHandler(mode="allow")
    handler.bind_executor(lambda _request: ProviderResponse(text="ok", model="fixture"))

    with pytest.raises(ValueError, match="must include a user message"):
        handler.sample(
            server_name="fixture",
            request=MCPSamplingRequest(
                messages=(
                    MCPSamplingMessage(role="assistant", content="orphan reply"),
                ),
                max_tokens=32,
            ),
        )


def test_sampling_bridge_preserves_assistant_ending_transcript() -> None:
    captured: list[ProviderRequest] = []
    handler = OpenMinionSamplingHandler(mode="allow")
    handler.bind_executor(
        lambda request: (
            captured.append(request) or ProviderResponse(text="ok", model="fixture")
        )
    )

    handler.sample(
        server_name="fixture",
        request=MCPSamplingRequest(
            messages=(
                MCPSamplingMessage(role="user", content="draft"),
                MCPSamplingMessage(role="assistant", content="partial answer"),
            ),
            max_tokens=32,
        ),
    )

    assert captured[0].user_message == ""
    assert [(item.role, item.content) for item in captured[0].history] == [
        ("user", "draft"),
        ("assistant", "partial answer"),
    ]


@pytest.mark.parametrize("max_tokens", (None, True, 0, -1, "32"))
def test_sampling_request_rejects_invalid_max_tokens(max_tokens) -> None:
    with pytest.raises(MCPProtocolError, match="positive integer"):
        MCPSamplingRequest(
            messages=(MCPSamplingMessage(role="user", content="hello"),),
            max_tokens=max_tokens,
        )
