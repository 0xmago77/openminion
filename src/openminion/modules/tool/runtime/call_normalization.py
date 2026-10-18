"""Normalize provider tool calls before runtime resolution."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from openminion.modules.tool.contracts import ProviderToolCall


def normalize_tool_call(call: ProviderToolCall) -> ProviderToolCall:
    tool_name = str(getattr(call, "name", "") or "").strip()
    raw_arguments = getattr(call, "arguments", {})
    arguments: dict[str, Any] = (
        dict(raw_arguments) if isinstance(raw_arguments, Mapping) else {}
    )

    nested_name = str(arguments.get("name", "") or "").strip()
    nested_arguments = arguments.get("arguments")
    if isinstance(nested_arguments, Mapping):
        if nested_name and (not tool_name or nested_name == tool_name):
            tool_name = nested_name
            arguments = dict(nested_arguments)
        elif not nested_name:
            arguments = dict(nested_arguments)

    if (
        "input" in arguments
        and isinstance(arguments.get("input"), Mapping)
        and len(arguments) == 1
    ):
        arguments = dict(arguments["input"])

    return ProviderToolCall(
        name=tool_name,
        arguments=arguments,
        id=str(getattr(call, "id", "") or ""),
        source=str(getattr(call, "source", "") or ""),
        depends_on=_normalized_depends_on(call),
    )


def _normalized_depends_on(call: ProviderToolCall) -> list[str]:
    raw_depends_on = getattr(call, "depends_on", []) or []
    if isinstance(raw_depends_on, str):
        values = [raw_depends_on]
    elif isinstance(raw_depends_on, (list, tuple, set)):
        values = list(raw_depends_on)
    else:
        values = []

    seen: set[str] = set()
    normalized: list[str] = []
    for dep in values:
        token = str(dep).strip()
        if token and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


__all__ = ["normalize_tool_call"]
