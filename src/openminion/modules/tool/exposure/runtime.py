"""Model-facing tool exposure and dispatch snapshots."""

import logging
from collections.abc import Mapping
from contextlib import nullcontext
from typing import Any

from openminion.modules.tool.contracts import (
    ProviderToolSpec,
    is_valid_model_tool_id,
    normalize_raw_model_tool_name,
)

from .service import ToolExposureService, exposure_scope

_LOG = logging.getLogger(__name__)


def _registration_lock(registry: Any) -> Any:
    read_lock = getattr(registry, "registration_read_lock", None)
    lock = read_lock() if callable(read_lock) else None
    if lock is None:
        lock = getattr(registry, "temporary_registration_lock", None)
    return lock if hasattr(type(lock), "__enter__") else nullcontext()


def _available_runtime_tool_names(registry: Any) -> set[str]:
    tools = getattr(registry, "_tools", None)
    if isinstance(tools, dict):
        return {str(name).strip() for name in tools if str(name).strip()}
    list_fn = getattr(registry, "list", None)
    if not callable(list_fn):
        return set()
    try:
        listed = list_fn()
    except Exception:
        return set()
    return (
        {str(name).strip() for name in listed if str(name).strip()}
        if isinstance(listed, dict)
        else set()
    )


def _canonical_specs(specs: list[ProviderToolSpec]) -> list[ProviderToolSpec]:
    canonical: dict[str, ProviderToolSpec] = {}
    for spec in specs:
        name = str(getattr(spec, "name", "") or "").strip()
        if not name or name in canonical:
            continue
        if not is_valid_model_tool_id(name):
            _LOG.debug("dropping non-canonical model exposure tool: %s", name)
            continue
        canonical[name] = spec
    return [canonical[name] for name in sorted(canonical)]


def _get_model_exposure_specs(
    registry: Any,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> list[ProviderToolSpec]:
    """Return canonical model-facing specs filtered by explicit exposure state."""

    if registry is None:
        return []
    specs: list[ProviderToolSpec] = []
    binding_manager_fn = getattr(registry, "_binding_manager", None)
    manager = None
    if callable(binding_manager_fn):
        try:
            manager = binding_manager_fn()
            specs = (
                list(
                    manager.model_provider_specs(
                        _available_runtime_tool_names(registry)
                    )
                )
                if manager is not None
                else []
            )
        except Exception:
            _LOG.warning(
                "manager-backed model tool exposure lookup failed", exc_info=True
            )
            specs = []
    if manager is None:
        model_specs_fn = getattr(registry, "model_provider_specs", None)
        if not callable(model_specs_fn):
            model_specs_fn = getattr(registry, "provider_specs", None)
        if not callable(model_specs_fn):
            return specs
        try:
            specs = list(model_specs_fn())
        except Exception:
            _LOG.warning("model_provider_specs lookup failed", exc_info=True)
            return []
    canonical = _canonical_specs(specs)
    service = getattr(registry, "exposure_service", None)
    if not isinstance(service, ToolExposureService):
        return canonical
    return service.filter_specs(canonical, **exposure_scope(metadata))


def get_model_exposure_specs(
    registry: Any,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> list[ProviderToolSpec]:
    with _registration_lock(registry):
        return _get_model_exposure_specs(registry, metadata=metadata)


def get_allowed_model_tool_names(
    registry: Any,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> set[str]:
    return {spec.name for spec in get_model_exposure_specs(registry, metadata=metadata)}


def _get_visible_tool_specs_and_dispatch_map(
    registry: Any,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> tuple[list[ProviderToolSpec], dict[str, dict[str, Any]]]:
    """Return visible tool specs plus canonical dispatch metadata."""

    if registry is None:
        return [], {}
    dispatch_map: dict[str, dict[str, Any]] = {}
    dispatch_map_fn = getattr(registry, "model_runtime_dispatch_map", None)
    if callable(dispatch_map_fn):
        try:
            raw_map = dispatch_map_fn()
            if isinstance(raw_map, Mapping):
                dispatch_map = {
                    str(key).strip(): dict(value)
                    for key, value in raw_map.items()
                    if str(key).strip() and isinstance(value, Mapping)
                }
        except Exception:
            dispatch_map = {}
    specs = get_model_exposure_specs(registry, metadata=metadata)
    visible = {spec.name for spec in specs}

    raw_tools = getattr(registry, "_tools", None)
    if isinstance(raw_tools, Mapping):
        provider_spec_for_name = getattr(registry, "provider_spec_for_name", None)
        service = getattr(registry, "exposure_service", None)
        scope = exposure_scope(metadata)
        for raw_name, raw_tool in raw_tools.items():
            if not bool(getattr(raw_tool, "prompt_visible_runtime_name", False)):
                continue
            name = str(raw_name or "").strip()
            if not name or name in visible:
                continue
            if isinstance(service, ToolExposureService):
                if service.decide(name, **scope).state != "visible":
                    continue
            spec = None
            if callable(provider_spec_for_name):
                try:
                    spec = provider_spec_for_name(name)
                except Exception:
                    spec = None
            if spec is None:
                continue
            specs.append(spec)
            visible.add(name)
            dispatch_map.setdefault(
                name,
                {
                    "runtime_binding_id": str(
                        getattr(raw_tool, "runtime_binding_id", "") or ""
                    ).strip(),
                    "runtime_tool_name": name,
                },
            )

    specs.sort(key=lambda item: str(getattr(item, "name", "") or ""))
    dispatch_map = {
        name: value for name, value in dispatch_map.items() if name in visible
    }
    return specs, dispatch_map


def get_visible_tool_specs_and_dispatch_map(
    registry: Any,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> tuple[list[ProviderToolSpec], dict[str, dict[str, Any]]]:
    with _registration_lock(registry):
        return _get_visible_tool_specs_and_dispatch_map(registry, metadata=metadata)


def resolve_forced_provider_tool_name(registry: Any, raw_name: str) -> str:
    """Resolve an explicitly forced name to an executable provider schema name."""
    token = str(raw_name or "").strip()
    if not token:
        return ""
    specs, _dispatch_map = get_visible_tool_specs_and_dispatch_map(registry)
    visible_names = {spec.name for spec in specs if spec.name}
    candidates = (normalize_raw_model_tool_name(token) or "", token)
    if visible_names:
        return next(
            (candidate for candidate in candidates if candidate in visible_names), ""
        )
    provider_specs = getattr(registry, "provider_specs", None)
    if not callable(provider_specs):
        return ""
    try:
        legacy_specs = provider_specs()
    except (AttributeError, TypeError):
        return ""
    legacy_by_name = {
        str(getattr(spec, "name", "") or "").strip(): spec
        for spec in legacy_specs
        if str(getattr(spec, "name", "") or "").strip()
    }
    for candidate in candidates:
        if not candidate:
            continue
        spec = legacy_by_name.get(candidate)
        if spec is not None:
            return str(getattr(spec, "name", "") or candidate)
    return ""


__all__ = [
    "get_allowed_model_tool_names",
    "get_model_exposure_specs",
    "get_visible_tool_specs_and_dispatch_map",
    "resolve_forced_provider_tool_name",
]
