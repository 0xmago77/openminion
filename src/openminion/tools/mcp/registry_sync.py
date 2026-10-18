"""Publish refreshed MCP discovery into one live tool registry."""

from __future__ import annotations

from threading import RLock
from typing import Any

from openminion.base.config.base import ConfigError
from openminion.modules.tool.errors import ToolRuntimeError
from openminion.modules.tool.registry import ToolRegistry

from .interfaces import (
    MCPCapabilityApplyResult,
    MCPToolRegistrationState,
)
from .plugin import build_mcp_specs
from .registrar import build_mcp_manifest
from .schemas import MCPUnsupportedSchemaError


def prepare_mcp_registration_state(
    runtime_config: Any,
    *,
    strict: bool,
) -> MCPToolRegistrationState:
    from .manager import MCPFleetManager

    manager = MCPFleetManager.from_runtime_config(runtime_config)
    state: MCPToolRegistrationState | None = None
    try:
        tools = tuple(manager.discover_tools(parallel=True))
        prompts = tuple(manager.discover_prompts(parallel=True))
        resources = tuple(manager.discover_resources(parallel=True))
        templates = tuple(manager.discover_resource_templates(parallel=True))
        required = {
            server.name
            for server in runtime_config.mcp_servers
            if server.enabled and server.required
        }
        failed = required.intersection(manager.failed_servers)
        if failed and strict:
            raise ToolRuntimeError(
                "MCP_REQUIRED_SERVER_UNAVAILABLE",
                f"Required MCP server discovery failed: {', '.join(sorted(failed))}",
                {"failed_servers": sorted(failed)},
            )
        state = MCPToolRegistrationState(
            manager=manager,
            discovered_tools=tools,
            discovered_prompts=prompts,
            discovered_resources=resources,
            discovered_resource_templates=templates,
            client_capability_state=manager.client_capability_state,
        )
        return state
    finally:
        if state is None:
            manager.close()


class MCPRegistrySynchronizer:
    """Stage and publish one fleet's refreshed MCP registration snapshot."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        registry_manager: Any,
        state: MCPToolRegistrationState,
    ) -> None:
        self._registry = registry
        self._registry_manager = registry_manager
        self._state = state
        self._lock = RLock()

    @property
    def state(self) -> MCPToolRegistrationState:
        return self._state

    def capability_changed(
        self,
        *,
        server_name: str,
        snapshots: dict[str, tuple[Any, ...]],
        added: dict[str, tuple[str, ...]],
        removed: dict[str, tuple[str, ...]],
    ) -> MCPCapabilityApplyResult:
        del added, removed
        with self._lock:
            if self._registry.mcp_manager is not self._state.manager:
                return MCPCapabilityApplyResult(status="stale")
            try:
                next_state = self._updated_state(
                    server_name=server_name,
                    snapshots=snapshots,
                )
                specs = build_mcp_specs(next_state)
                manifest = build_mcp_manifest(next_state)
                schemas = self._runtime_schemas(specs)
                staged_manager = self._registry_manager.staged_with_module_manifest(
                    manifest,
                    runtime_tool_schemas=schemas,
                )
            except (ConfigError, MCPUnsupportedSchemaError, ToolRuntimeError) as exc:
                return MCPCapabilityApplyResult(status="failed", error=str(exc))

            try:
                published = self._registry.replace_mcp_tools(
                    specs,
                    registry_manager=staged_manager,
                    expected_manager=self._state.manager,
                )
            except ToolRuntimeError as exc:
                return MCPCapabilityApplyResult(status="failed", error=str(exc))
            if not published:
                return MCPCapabilityApplyResult(status="stale")
            self._registry_manager = staged_manager
            self._state = next_state
            return MCPCapabilityApplyResult(status="applied")

    def activate(
        self,
        *,
        state: MCPToolRegistrationState,
        expected_manager: Any,
    ) -> MCPCapabilityApplyResult:
        """Publish a fully discovered replacement fleet for same-process reload."""
        with self._lock:
            state.manager.bind_capability_change_listener(self)
            try:
                specs = build_mcp_specs(state)
                staged_manager = self._registry_manager.staged_with_module_manifest(
                    build_mcp_manifest(state),
                    runtime_tool_schemas=self._runtime_schemas(specs),
                )
            except (ConfigError, MCPUnsupportedSchemaError, ToolRuntimeError) as exc:
                state.manager.bind_capability_change_listener(None)
                return MCPCapabilityApplyResult(status="failed", error=str(exc))
            try:
                published = self._registry.replace_mcp_tools(
                    specs,
                    registry_manager=staged_manager,
                    expected_manager=expected_manager,
                    mcp_manager=state.manager,
                )
            except ToolRuntimeError as exc:
                state.manager.bind_capability_change_listener(None)
                return MCPCapabilityApplyResult(status="failed", error=str(exc))
            if not published:
                state.manager.bind_capability_change_listener(None)
                return MCPCapabilityApplyResult(status="stale")
            self._registry_manager = staged_manager
            self._state = state
            return MCPCapabilityApplyResult(status="applied")

    def _runtime_schemas(self, mcp_specs: tuple[Any, ...]) -> dict[str, dict[str, Any]]:
        return {
            spec.name: dict(schema)
            for spec in mcp_specs
            if isinstance(
                schema := getattr(spec, "parameters_schema", None),
                dict,
            )
        }

    def _updated_state(
        self,
        *,
        server_name: str,
        snapshots: dict[str, tuple[Any, ...]],
    ) -> MCPToolRegistrationState:
        def _replace(items: tuple[Any, ...], primitive: str) -> tuple[Any, ...]:
            replacement = snapshots.get(primitive)
            if replacement is None:
                return items
            retained = tuple(
                item
                for item in items
                if str(getattr(item, "server_name", "") or "") != server_name
            )
            return retained + tuple(replacement)

        return MCPToolRegistrationState(
            manager=self._state.manager,
            discovered_tools=_replace(self._state.discovered_tools, "tools"),
            discovered_prompts=_replace(self._state.discovered_prompts, "prompts"),
            discovered_resources=_replace(
                self._state.discovered_resources,
                "resources",
            ),
            discovered_resource_templates=_replace(
                self._state.discovered_resource_templates,
                "resource_templates",
            ),
            client_capability_state=self._state.client_capability_state,
        )


__all__ = ["MCPRegistrySynchronizer", "prepare_mcp_registration_state"]
