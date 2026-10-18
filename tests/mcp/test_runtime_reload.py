from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from openminion.base.config.core import OpenMinionConfig
from openminion.base.config.io import save_config
from openminion.base.config.mcp import MCPServerConfig
from openminion.modules.tool.bootstrap import build_runtime_bootstrap
from openminion.modules.tool.errors import ToolRuntimeError
from openminion.tools.mcp.reload import reload_runtime_mcp

from .test_list_changed_notifications import _runtime_config


class _IdleRuntimeManager:
    @staticmethod
    def has_foreground_work() -> bool:
        return False

    @staticmethod
    def list_agents() -> list[object]:
        return []


def _runtime(bootstrap: object, config: OpenMinionConfig, path: Path) -> object:
    return SimpleNamespace(
        runtime_manager=_IdleRuntimeManager(),
        tools=bootstrap.registry,
        config_path=path,
        home_root=path.parent,
        config=config,
        config_manager=None,
        agent=SimpleNamespace(),
        _agent_services={},
    )


def test_reload_removes_and_restores_mcp_tools_in_same_registry(tmp_path: Path) -> None:
    initial_runtime = _runtime_config()
    bootstrap = build_runtime_bootstrap(config=initial_runtime, strict=True)
    config = OpenMinionConfig()
    config.runtime.mcp_servers = list(initial_runtime.mcp_servers)
    path = tmp_path / "config.json"
    save_config(config, str(path), home_root=tmp_path)
    runtime = _runtime(bootstrap, config, path)
    registry = runtime.tools
    try:
        assert "mcp.fixture.echo_text" in registry.list()

        disabled = OpenMinionConfig()
        save_config(disabled, str(path), home_root=tmp_path)
        result = reload_runtime_mcp(runtime)
        assert result == {"status": "reloaded", "servers": 0, "runtime_tools": 0}
        assert not any(name.startswith("mcp.") for name in registry.list())

        restored = OpenMinionConfig()
        restored.runtime.mcp_servers = list(initial_runtime.mcp_servers)
        save_config(restored, str(path), home_root=tmp_path)
        result = reload_runtime_mcp(runtime)
        assert result["servers"] == 1
        assert "mcp.fixture.echo_text" in registry.list()
    finally:
        manager = registry.mcp_manager
        if manager is not None:
            manager.close()


def test_reload_rejects_non_idle_runtime(tmp_path: Path) -> None:
    bootstrap = build_runtime_bootstrap(config=_runtime_config(), strict=True)
    config = OpenMinionConfig()
    path = tmp_path / "config.json"
    save_config(config, str(path), home_root=tmp_path)
    runtime = _runtime(bootstrap, config, path)
    runtime.runtime_manager = SimpleNamespace(
        has_foreground_work=lambda: True,
        list_agents=lambda: [],
    )
    try:
        try:
            reload_runtime_mcp(runtime)
        except RuntimeError as exc:
            assert str(exc) == "MCP reload requires an idle runtime"
        else:
            raise AssertionError("reload should reject active work")
    finally:
        bootstrap.mcp_manager.close()


def test_reload_failure_keeps_existing_fleet_and_tools(tmp_path: Path) -> None:
    initial_runtime = _runtime_config()
    bootstrap = build_runtime_bootstrap(config=initial_runtime, strict=True)
    config = OpenMinionConfig()
    config.runtime.mcp_servers = list(initial_runtime.mcp_servers)
    path = tmp_path / "config.json"
    save_config(config, str(path), home_root=tmp_path)
    runtime = _runtime(bootstrap, config, path)
    registry = runtime.tools
    old_manager = registry.mcp_manager
    broken = OpenMinionConfig()
    broken.runtime.mcp_servers = [
        MCPServerConfig(
            name="broken",
            transport="stdio",
            command=["/definitely/missing/openminion-mcp"],
            required=True,
        )
    ]
    save_config(broken, str(path), home_root=tmp_path)
    try:
        with pytest.raises(
            ToolRuntimeError,
            match="Required MCP server discovery failed",
        ):
            reload_runtime_mcp(runtime)

        assert registry.mcp_manager is old_manager
        assert "mcp.fixture.echo_text" in registry.list()
        result = registry.get("mcp.fixture.echo_text").handler({"text": "still live"}, None)
        assert result["data"]["structured_content"]["echo"] == "still live"
    finally:
        if old_manager is not None:
            old_manager.close()


def test_reload_replaces_synchronizer_and_preserves_non_mcp_runtime_config(
    tmp_path: Path,
) -> None:
    initial_runtime = _runtime_config()
    bootstrap = build_runtime_bootstrap(config=initial_runtime, strict=True)
    config = OpenMinionConfig()
    config.runtime.mcp_servers = list(initial_runtime.mcp_servers)
    config.runtime.chat_turn_timeout_seconds = 321.0
    path = tmp_path / "config.json"
    save_config(config, str(path), home_root=tmp_path)
    runtime = _runtime(bootstrap, config, path)
    managed_config = OpenMinionConfig()
    managed_config.runtime.mcp_servers = list(initial_runtime.mcp_servers)
    reset_calls: list[str] = []
    runtime.config_manager = SimpleNamespace(
        base_config=managed_config,
        reset=lambda: reset_calls.append("reset"),
    )
    registry = runtime.tools
    old_synchronizer = registry.mcp_synchronizer
    disabled = OpenMinionConfig()
    disabled.runtime.chat_turn_timeout_seconds = 7.0
    save_config(disabled, str(path), home_root=tmp_path)
    try:
        reload_runtime_mcp(runtime)

        assert registry.mcp_synchronizer is not old_synchronizer
        assert runtime.config.runtime.chat_turn_timeout_seconds == 321.0
        assert managed_config.runtime.mcp_servers == []
        assert reset_calls == ["reset"]
        assert old_synchronizer is not None
        result = old_synchronizer.capability_changed(
            server_name="fixture",
            snapshots={"tools": ()},
            added={"tools": ()},
            removed={"tools": ()},
        )
        assert result.status == "stale"
        assert not any(name.startswith("mcp.") for name in registry.list())
    finally:
        manager = registry.mcp_manager
        if manager is not None:
            manager.close()
