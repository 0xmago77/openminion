"""Runtime resolution and atomic dynamic publication for tool registries."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from openminion.modules.tool.errors import ToolRuntimeError
from openminion.modules.tool.runtime.dispatch import resolve_binding_for_call

from .catalog import ToolPolicyProfile, ToolSpec

if TYPE_CHECKING:
    from openminion.modules.tool.registry import ToolRegistry
    from openminion.modules.tool.runtime.manager import ToolRegistryManager
    from openminion.tools.mcp.interfaces import MCPFleetHandle


def replace_mcp_tools(
    registry: ToolRegistry,
    specs: Sequence[ToolSpec],
    *,
    registry_manager: ToolRegistryManager,
    expected_manager: MCPFleetHandle | None,
    mcp_manager: MCPFleetHandle | None = None,
) -> bool:
    names = [spec.name for spec in specs]
    if len(names) != len(set(names)) or any(
        not name.startswith("mcp.") for name in names
    ):
        raise ToolRuntimeError(
            "INVALID_ARGUMENT",
            "MCP replacement specs must have unique mcp.* names.",
        )

    from openminion.modules.tool.registry import ToolRegistry

    with registry.temporary_registration_lock:
        if registry.mcp_manager is not expected_manager:
            return False
        staged = ToolRegistry()
        staged._tools = {
            name: tool
            for name, tool in registry._tools.items()
            if not name.startswith("mcp.")
        }
        staged._category_index = {
            category: {name for name in category_names if not name.startswith("mcp.")}
            for category, category_names in registry._category_index.items()
        }
        for spec in specs:
            staged.register(spec)
        registry._tools = staged._tools
        registry._category_index = staged._category_index
        registry._registry_manager = registry_manager
        if mcp_manager is not None:
            registry.mcp_manager = mcp_manager
        return True


def policy_for(registry: ToolRegistry, tool_name: str) -> ToolPolicyProfile:
    key, tool = resolve_runtime_tool(registry, str(tool_name or "").strip())
    if tool is None:
        return ToolPolicyProfile(
            tool_name=key or "unknown",
            required_scopes_all=frozenset({"tool.execute"}),
            risk="medium",
            budget_cost=1,
        )
    if isinstance(tool, ToolSpec):
        min_scope = str(tool.min_scope or "READ_ONLY").strip().upper()
        required_scopes = {"tool.execute"}
        if min_scope in {"POWER_USER", "UI_AUTOMATION"}:
            required_scopes.add("tool.execute.elevated")
        risk = "high" if tool.dangerous else "medium"
        return ToolPolicyProfile(
            tool_name=str(tool.name or key).strip() or key or "unknown",
            required_scopes_all=frozenset(required_scopes),
            risk=risk,
            budget_cost=2 if risk == "high" else 1,
        )
    policy = tool.execution_policy()
    try:
        budget_cost = max(1, int(policy.budget_cost))
    except (TypeError, ValueError):
        budget_cost = 1
    return ToolPolicyProfile(
        tool_name=str(tool.name or key).strip() or key or "unknown",
        required_scopes_all=frozenset(policy.required_scopes_all),
        risk=str(policy.risk or "medium").strip().lower() or "medium",
        budget_cost=budget_cost,
    )


def sidecar_for(registry: ToolRegistry, tool_name: str) -> str:
    _, tool = resolve_runtime_tool(registry, str(tool_name or "").strip())
    sidecar = getattr(tool, "sidecar", "") if tool is not None else ""
    return str(sidecar or "").strip()


def resolve_runtime_tool(registry: ToolRegistry, key: str) -> tuple[str, Any | None]:
    with registry.temporary_registration_lock:
        tool = registry._tools.get(key)
        if tool is not None:
            return key, tool
        manager = binding_manager(registry)
        model_tool_id = manager.normalize_raw_name(key)
        if model_tool_id:
            runtime_name = manager.model_to_runtime_tool_map(set(registry._tools)).get(
                model_tool_id
            )
            if runtime_name and (tool := registry._tools.get(runtime_name)) is not None:
                return runtime_name, tool
        resolution = resolve_binding_for_call(
            raw_tool_name=key,
            available_tool_names=tuple(registry._tools),
            manager=manager,
        )
        if resolution is not None and resolution.runtime_tool_name:
            tool = registry._tools.get(resolution.runtime_tool_name)
            if tool is not None:
                return resolution.runtime_tool_name, tool
        return key, None


def binding_manager(registry: ToolRegistry) -> ToolRegistryManager:
    manager = getattr(registry, "_registry_manager", None)
    if manager is not None:
        return manager
    base_registry = getattr(registry, "_base_registry", None)
    if base_registry is not None:
        return binding_manager(base_registry)

    from openminion.modules.tool.runtime.dispatch import get_registry_manager

    manager = get_registry_manager()
    if manager.model_provider_specs(set(registry._tools)):
        return manager
    try:
        from openminion.modules.tool.bootstrap import wire_default_tool_registry_manager

        wire_default_tool_registry_manager()
        manager = get_registry_manager()
    except Exception:
        pass
    return manager


__all__ = [
    "binding_manager",
    "policy_for",
    "replace_mcp_tools",
    "resolve_runtime_tool",
    "sidecar_for",
]
