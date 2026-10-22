from typing import Any, TYPE_CHECKING

from openminion.modules.tool.schema_service import ToolSchemaService
from openminion.modules.tool.registry.runtime import binding_manager

from .parser import normalize_tool_name_for_brain

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..runner import BrainRunner


_TOOL_SCHEMA_SERVICE = ToolSchemaService()


def _normalize_execution_tool_name(
    raw_name: str,
    *,
    registry: Any | None = None,
) -> str | None:
    token = str(raw_name or "").strip()
    if not token:
        return None
    manager = binding_manager(registry)
    return manager.normalize_raw_name(token) or normalize_tool_name_for_brain(
        token,
        registry=registry,
    )


def collect_runtime_tool_schemas(
    runner: "BrainRunner", *, metadata: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    tool_api = getattr(runner, "tool_api", None)
    registry = getattr(tool_api, "registry", None)
    if registry is None:
        return []
    metadata = dict(metadata or {})
    context_builder = getattr(tool_api, "_build_execution_context_builder", None)
    if context_builder is not None:
        context_builder().project_security_lab(
            metadata, str(metadata.get("session_id", "") or "")
        )
    schemas = _TOOL_SCHEMA_SERVICE.collect_execution_tool_schemas(
        registry=registry,
        normalize_name=lambda raw_name: _normalize_execution_tool_name(
            raw_name,
            registry=registry,
        ),
        metadata=metadata,
    )
    is_allowed = getattr(tool_api, "is_tool_allowed", None)
    if not callable(is_allowed):
        return schemas
    return [
        item for item in schemas if is_allowed(str(item.get("name", "") or "").strip())
    ]


def collect_runtime_tool_names(
    runner: "BrainRunner", *, metadata: dict[str, Any] | None = None
) -> frozenset[str]:
    return frozenset(
        name
        for item in collect_runtime_tool_schemas(runner, metadata=metadata)
        if (name := str(item.get("name", "") or "").strip())
    )


def build_prompt_tool_schemas(
    runner: "BrainRunner", *, user_input: str | None
) -> list[dict[str, Any]]:
    raw_tools = collect_runtime_tool_schemas(runner)
    return _TOOL_SCHEMA_SERVICE.build_prompt_tool_schemas(
        query=user_input or "",
        tool_schemas=raw_tools,
    )


tool_schema_stub = _TOOL_SCHEMA_SERVICE.tool_stub
trim_text = _TOOL_SCHEMA_SERVICE.trim_text
tool_description = _TOOL_SCHEMA_SERVICE.tool_description
tool_parameters = _TOOL_SCHEMA_SERVICE.tool_parameters
