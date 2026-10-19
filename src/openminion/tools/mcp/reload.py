"""Same-process MCP configuration reload."""

from __future__ import annotations

from typing import Any

from openminion.api.core.infrastructure import bind_mcp_sampling_executor
from openminion.base.config.io import load_config

from .registry_sync import MCPRegistrySynchronizer, prepare_mcp_registration_state


def reload_runtime_mcp(runtime: Any) -> dict[str, Any]:
    manager = runtime.runtime_manager
    if manager.has_foreground_work() or any(
        status.active_turns or status.queued_turns for status in manager.list_agents()
    ):
        raise RuntimeError("MCP reload requires an idle runtime")
    if runtime.config_path is None:
        raise RuntimeError("MCP reload requires a runtime config path")

    loaded = load_config(str(runtime.config_path), home_root=runtime.home_root)
    state = prepare_mcp_registration_state(loaded.runtime, strict=True)
    old_manager = runtime.tools.mcp_manager
    synchronizer = MCPRegistrySynchronizer(
        registry=runtime.tools,
        registry_manager=runtime.tools.registry_manager,
        state=state,
    )
    _bind_sampling_executors(runtime, state.manager)
    result = synchronizer.activate(
        state=state,
        expected_manager=old_manager,
    )
    if result.status != "applied":
        state.manager.close()
        raise RuntimeError(result.error or f"MCP reload was {result.status}")

    runtime.tools.mcp_synchronizer = synchronizer
    _update_runtime_config(runtime, loaded)
    if old_manager is not None and old_manager is not state.manager:
        old_manager.bind_capability_change_listener(None)
        old_manager.close()
    return {
        "status": "reloaded",
        "servers": len(loaded.runtime.mcp_servers),
        "runtime_tools": len(state.added_runtime_tools),
    }


def _bind_sampling_executors(runtime: Any, manager: Any) -> None:
    services = [runtime.agent, *runtime._agent_services.values()]
    seen: set[int] = set()
    for service in services:
        if id(service) in seen:
            continue
        seen.add(id(service))
        bind_mcp_sampling_executor(runtime.tools, service, manager=manager)


def _update_runtime_config(runtime: Any, loaded: Any) -> None:
    target = runtime.config.runtime
    source = loaded.runtime
    target.mcp_servers = list(source.mcp_servers)
    target.mcp_sampling_mode = source.mcp_sampling_mode
    target.mcp_discovery_cache_ttl_seconds = source.mcp_discovery_cache_ttl_seconds
    if runtime.config_manager is not None:
        managed = runtime.config_manager.base_config.runtime
        managed.mcp_servers = list(source.mcp_servers)
        managed.mcp_sampling_mode = source.mcp_sampling_mode
        managed.mcp_discovery_cache_ttl_seconds = source.mcp_discovery_cache_ttl_seconds
        runtime.config_manager.reset()


__all__ = ["reload_runtime_mcp"]
