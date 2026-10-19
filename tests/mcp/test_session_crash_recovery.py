from __future__ import annotations

import atexit
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from openminion.base.config.mcp import MCPServerConfig
from openminion.base.config.runtime import RuntimeConfig
from openminion.tools.mcp.manager import (
    MCPFleetManager,
    MCPServerSession,
)
from openminion.tools.mcp.transport import (
    MCPProtocolError,
    MCPRemoteTransportError,
    MCPServerUnavailableError,
)
from openminion.tools.mcp.results import MCPCallError


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
                request_timeout_seconds=5.0,
                startup_timeout_seconds=5.0,
            )
        ]
    )


def test_transparent_restart_recovers_once_after_process_exit() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    try:
        first = manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "before crash"},
        )
        assert first["ok"] is True

        session = manager._sessions["fixture"]
        manager.close_server("fixture")
        recovered = manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "after crash"},
        )

        assert recovered["ok"] is True
        assert recovered["content"] == "echo: after crash"
        assert session._restart_total == 1
        assert len(session._restart_history) == 1
    finally:
        manager.close()


def test_fourth_crash_inside_window_raises_unrecoverable_error() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    try:
        session = manager._sessions["fixture"]
        manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "prime"},
        )

        for _ in range(3):
            manager.close_server("fixture")
            result = manager.call_tool(
                server_name="fixture",
                remote_name="echo-text",
                arguments={"text": "recover"},
            )
            assert result["ok"] is True

        manager.close_server("fixture")
        with pytest.raises(MCPServerUnavailableError) as excinfo:
            manager.call_tool(
                server_name="fixture",
                remote_name="echo-text",
                arguments={"text": "boom"},
            )

        assert excinfo.value.reason_code == "mcp_server_crashed_unrecoverable"
        assert "unrecoverable" in str(excinfo.value).lower()
        assert len(session._restart_history) == 3
        assert session._restart_total == 3
    finally:
        manager.close()


def test_concurrent_recovery_restarts_stdio_session_once() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    try:
        session = manager._sessions["fixture"]
        manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "prime"},
        )
        manager.close_server("fixture")
        observed_restart_total = session.restart_total

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    session._restart_transport,
                    observed_restart_total=observed_restart_total,
                )
                for _ in range(2)
            ]
            for future in futures:
                future.result(timeout=5)

        assert session.restart_total == observed_restart_total + 1
        result = manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "recovered"},
        )
        assert result["ok"] is True
    finally:
        manager.close()


def test_stdio_discovery_crash_does_not_retry_legacy_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _runtime_config()
    session = MCPServerSession(config.mcp_servers[0])
    call_count = {"request": 0}

    def _explode(**kwargs):
        del kwargs
        call_count["request"] += 1
        raise MCPServerUnavailableError(
            "initialize died",
            reason_code="mcp_server_unavailable",
        )

    monkeypatch.setattr(session._transport, "start", lambda: None)
    monkeypatch.setattr(session._transport, "close", lambda: None)
    monkeypatch.setattr(session._transport, "request", _explode)

    with pytest.raises(MCPServerUnavailableError) as excinfo:
        session.call_tool(remote_name="echo-text", arguments={"text": "x"})

    assert excinfo.value.reason_code == "mcp_server_unavailable"
    assert call_count["request"] == 1
    assert session._restart_total == 0
    assert len(session._restart_history) == 0


def test_interrupted_tool_call_is_not_replayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _runtime_config()
    session = MCPServerSession(config.mcp_servers[0])
    received = {"count": 0}

    def _fail_after_receipt(**kwargs):
        del kwargs
        received["count"] += 1
        raise MCPServerUnavailableError(
            "connection lost after receipt",
            reason_code="mcp_server_unavailable",
        )

    session._initialized = True  # noqa: SLF001
    monkeypatch.setattr(session._transport, "is_running", lambda: True)
    monkeypatch.setattr(session._transport, "request", _fail_after_receipt)

    with pytest.raises(MCPCallError) as excinfo:
        session.call_tool(remote_name="side-effect", arguments={"value": 1})

    assert excinfo.value.reason_code == "mcp_outcome_uncertain"
    assert received["count"] == 1
    assert session.restart_total == 0


def test_successful_call_clears_stale_server_failure() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    try:
        manager._record_failed_server(  # noqa: SLF001
            server_name="fixture",
            primitive="tools",
            exc=MCPProtocolError("stale failure"),
        )

        result = manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "recovered"},
        )

        assert result["ok"] is True
        assert manager.failed_servers == {}
    finally:
        manager.close()


def test_successful_tool_call_preserves_other_primitive_failure() -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    try:
        manager._record_failed_server(  # noqa: SLF001
            server_name="fixture",
            primitive="prompts",
            exc=MCPProtocolError("prompt discovery failed"),
        )

        result = manager.call_tool(
            server_name="fixture",
            remote_name="echo-text",
            arguments={"text": "recovered"},
        )

        assert result["ok"] is True
        assert manager.failed_servers["fixture"].primitive == "prompts"
    finally:
        manager.close()


def test_parallel_discovery_records_remote_transport_error(monkeypatch) -> None:
    manager = MCPFleetManager.from_runtime_config(_runtime_config())
    session = manager._sessions["fixture"]

    def _fail() -> list[object]:
        raise MCPRemoteTransportError(
            "remote discovery failed",
            reason_code="mcp_http_error",
        )

    monkeypatch.setattr(session, "list_tools", _fail)
    try:
        assert manager.discover_tools(parallel=True) == []
        assert manager.failed_servers["fixture"].reason_code == "mcp_http_error"
    finally:
        manager.close()


def test_manager_close_unregisters_atexit_once(monkeypatch) -> None:
    registered: list[object] = []
    unregistered: list[object] = []
    token_store_closes: list[str] = []
    monkeypatch.setattr(atexit, "register", registered.append)
    monkeypatch.setattr(atexit, "unregister", unregistered.append)
    token_store = type(
        "TokenStore",
        (),
        {"close": lambda self: token_store_closes.append("closed")},
    )()
    manager = MCPFleetManager(
        servers=_runtime_config().mcp_servers,
        token_store=token_store,
    )

    manager.close()
    manager.close()

    assert unregistered == registered
    assert token_store_closes == ["closed"]


def test_disabled_server_is_not_started() -> None:
    config = _runtime_config()
    config.mcp_servers[0].enabled = False

    manager = MCPFleetManager.from_runtime_config(config)
    try:
        assert manager.has_servers() is False
        assert manager.server_status_snapshot() == {}
        assert manager.discover_tools() == []
    finally:
        manager.close()
