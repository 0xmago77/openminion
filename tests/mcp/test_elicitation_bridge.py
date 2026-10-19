from __future__ import annotations

import sys
from pathlib import Path

import pytest

from openminion.base.config.mcp import MCPServerConfig
from openminion.base.config.runtime import RuntimeConfig
from openminion.tools.mcp.elicitation import OpenMinionElicitationHandler
from openminion.tools.mcp.errors import MCPProtocolError
from openminion.tools.mcp.manager import MCPFleetManager
from openminion.tools.mcp.schemas import (
    MCPArgumentValidationError,
    MCPElicitationRequest,
    MCPElicitationResult,
)


FIXTURE_SERVER_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "mock_mcp_server.py"
)


def _runtime_config() -> RuntimeConfig:
    return RuntimeConfig(
        mcp_servers=[
            MCPServerConfig(
                name="Fixture",
                transport="stdio",
                trusted=True,
                command=[sys.executable, str(FIXTURE_SERVER_PATH)],
                env={
                    "MOCK_MCP_ENABLE_CLIENT_REQUEST_TOOLS": "1",
                    "MOCK_MCP_REQUIRE_CLIENT_CAPABILITIES": "elicitation",
                },
                request_timeout_seconds=5.0,
                startup_timeout_seconds=5.0,
            )
        ],
    )


def test_default_elicitation_declines_in_noninteractive_mode() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    try:
        result = manager.call_tool(
            server_name="fixture",
            remote_name="request-elicitation",
            arguments={},
        )

        assert result["ok"] is True
        assert result["content"] == "elicitation: decline"
        events = manager.mcp_elicitation_events()
        assert events[-1]["action"] == "decline"
        assert events[-1]["request_mode"] == "form"
    finally:
        manager.close()


def test_interactive_elicitation_responder_accepts_form_content() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    captured: list[MCPElicitationRequest] = []

    def _responder(request: MCPElicitationRequest) -> MCPElicitationResult:
        captured.append(request)
        return MCPElicitationResult(
            action="accept",
            content={"display_name": "Taylor"},
        )

    manager.bind_elicitation_responder(_responder)
    try:
        result = manager.call_tool(
            server_name="fixture",
            remote_name="request-elicitation",
            arguments={},
        )

        assert result["ok"] is True
        assert result["content"] == "elicitation: accept (Taylor)"
        assert captured
        assert captured[0].message == "Please provide a display name."
        events = manager.mcp_elicitation_events()
        assert events[-1]["action"] == "accept"
    finally:
        manager.close()


def test_elicitation_handler_declines_unsupported_url_request() -> None:
    handler = OpenMinionElicitationHandler(mode="interactive", url_supported=False)
    result = handler.elicit(
        server_name="fixture",
        request=MCPElicitationRequest(
            mode="url",
            message="Open this authorization URL.",
            url="https://example.invalid/auth",
        ),
    )

    assert result.action == "decline"
    assert result.content is None
    assert handler.events()[-1].request_mode == "url"


@pytest.mark.parametrize(
    "result",
    [
        MCPElicitationResult(action="later"),
        MCPElicitationResult(action="decline", content={"reason": "no"}),
    ],
)
def test_elicitation_handler_rejects_invalid_action_content(
    result: MCPElicitationResult,
) -> None:
    handler = OpenMinionElicitationHandler(mode="interactive")
    handler.bind_responder(lambda _request: result)

    with pytest.raises(MCPProtocolError):
        handler.elicit(
            server_name="fixture",
            request=MCPElicitationRequest(mode="form", message="Choose"),
        )


def test_elicitation_handler_validates_accepted_form_content() -> None:
    handler = OpenMinionElicitationHandler(mode="interactive")
    handler.bind_responder(
        lambda _request: MCPElicitationResult(
            action="accept", content={"count": "not-an-integer"}
        )
    )

    with pytest.raises(MCPArgumentValidationError):
        handler.elicit(
            server_name="fixture",
            request=MCPElicitationRequest(
                mode="form",
                message="Count",
                requested_schema={
                    "type": "object",
                    "properties": {"count": {"type": "integer"}},
                    "required": ["count"],
                },
            ),
        )


def test_elicitation_handler_rejects_invalid_responder_return() -> None:
    handler = OpenMinionElicitationHandler(mode="interactive")
    handler.bind_responder(lambda _request: object())  # type: ignore[arg-type]

    with pytest.raises(MCPProtocolError, match="invalid result"):
        handler.elicit(
            server_name="fixture",
            request=MCPElicitationRequest(mode="form", message="Choose"),
        )


@pytest.mark.parametrize("result", [{}, {"action": "decline", "content": "bad"}])
def test_elicitation_handler_rejects_malformed_result_dict(result: dict) -> None:
    handler = OpenMinionElicitationHandler(mode="interactive")
    handler.bind_responder(lambda _request: result)

    with pytest.raises(MCPProtocolError):
        handler.elicit(
            server_name="fixture",
            request=MCPElicitationRequest(mode="form", message="Choose"),
        )


def test_elicitation_handler_rejects_url_content() -> None:
    handler = OpenMinionElicitationHandler(mode="interactive", url_supported=True)
    handler.bind_responder(
        lambda _request: MCPElicitationResult(
            action="accept", content={"authorization_code": "secret"}
        )
    )

    with pytest.raises(MCPProtocolError, match="URL elicitation must omit content"):
        handler.elicit(
            server_name="fixture",
            request=MCPElicitationRequest(
                mode="url",
                message="Authorize",
                url="https://example.invalid/authorize",
            ),
        )
