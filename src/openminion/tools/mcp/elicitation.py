"""OpenMinion MCP elicitation bridge."""

import time
from dataclasses import dataclass
from typing import Any, Callable

from .errors import MCPProtocolError
from .schemas import (
    MCPElicitationRequest,
    MCPElicitationResult,
    validate_mcp_value,
)

ElicitationResponder = Callable[
    [MCPElicitationRequest], MCPElicitationResult | dict[str, Any]
]


@dataclass(frozen=True)
class MCPElicitationAuditEvent:
    server_name: str
    mode: str
    request_mode: str
    action: str
    elicitation_id: str = ""
    timestamp: float = 0.0


class OpenMinionElicitationHandler:
    """Typed bridge for user-visible MCP elicitation requests."""

    def __init__(self, *, mode: str = "decline", url_supported: bool = False) -> None:
        self._mode = str(mode or "decline").strip().lower()
        self._url_supported = bool(url_supported)
        self._responder: ElicitationResponder | None = None
        self._events: list[MCPElicitationAuditEvent] = []

    def bind_responder(self, responder: ElicitationResponder) -> None:
        self._responder = responder
        self._mode = "interactive"

    def set_url_supported(self, value: bool) -> None:
        self._url_supported = bool(value)

    def events(self) -> list[MCPElicitationAuditEvent]:
        return list(self._events)

    def elicit(
        self,
        *,
        server_name: str,
        request: MCPElicitationRequest,
    ) -> MCPElicitationResult:
        request_mode = request.mode.strip().lower() or "form"
        if request_mode == "url" and not self._url_supported:
            result = MCPElicitationResult(action="decline")
            self._record(server_name=server_name, request=request, result=result)
            return result
        if self._mode != "interactive" or self._responder is None:
            result = MCPElicitationResult(action="decline")
            self._record(server_name=server_name, request=request, result=result)
            return result

        result = _coerce_elicitation_result(self._responder(request))
        _validate_elicitation_result(request=request, result=result)
        self._record(server_name=server_name, request=request, result=result)
        return result

    def _record(
        self,
        *,
        server_name: str,
        request: MCPElicitationRequest,
        result: MCPElicitationResult,
    ) -> None:
        self._events.append(
            MCPElicitationAuditEvent(
                server_name=server_name,
                mode=self._mode,
                request_mode=request.mode.strip(),
                action=result.action.strip(),
                elicitation_id=request.elicitation_id.strip(),
                timestamp=time.time(),
            )
        )


def _coerce_elicitation_result(
    value: MCPElicitationResult | dict[str, Any],
) -> MCPElicitationResult:
    if isinstance(value, MCPElicitationResult):
        return value
    if isinstance(value, dict):
        content = value.get("content")
        if content is not None and not isinstance(content, dict):
            raise MCPProtocolError("MCP elicitation content must be an object.")
        return MCPElicitationResult(
            action=str(value.get("action", "") or "").strip(),
            content=dict(content) if content is not None else None,
        )
    raise MCPProtocolError("MCP elicitation responder returned an invalid result.")


def _validate_elicitation_result(
    *, request: MCPElicitationRequest, result: MCPElicitationResult
) -> None:
    action = result.action.strip()
    if action not in {"accept", "decline", "cancel"}:
        raise MCPProtocolError(f"MCP elicitation returned invalid action {action!r}.")
    if action != "accept":
        if result.content is not None:
            raise MCPProtocolError(
                "Declined or cancelled MCP elicitation must omit content."
            )
        return
    if request.mode.strip().lower() == "url":
        if result.content is not None:
            raise MCPProtocolError("Accepted URL elicitation must omit content.")
        return
    if result.content is None:
        raise MCPProtocolError("Accepted MCP form elicitation must include content.")
    validate_mcp_value(
        schema=request.requested_schema,
        value=result.content,
        value_path="content",
    )


__all__ = [
    "ElicitationResponder",
    "MCPElicitationAuditEvent",
    "OpenMinionElicitationHandler",
]
