"""Normalize MCP prompt, resource, and tool results."""

import json
from typing import Any

from .errors import MCPProtocolError
from .schemas import (
    MCPArgumentValidationError,
    MCPCompletionResult,
    validate_mcp_value,
)


class MCPManagerError(RuntimeError):
    """Base MCP manager error."""


class MCPCallError(MCPManagerError):
    """Raised when an MCP tool call returns an error envelope."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "mcp_upstream_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code.strip()
        self.details = dict(details or {})


def coerce_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_completion_result(result: dict[str, Any]) -> MCPCompletionResult:
    completion = result.get("completion")
    if not isinstance(completion, dict):
        raise _shape_error("completion must be an object")
    raw_values = completion.get("values")
    if not isinstance(raw_values, list) or any(
        not isinstance(item, str) for item in raw_values
    ):
        raise _shape_error("completion.values must be an array of strings")
    raw_total = completion.get("total")
    if raw_total is not None and (
        isinstance(raw_total, bool) or not isinstance(raw_total, int)
    ):
        raise _shape_error("completion.total must be an integer")
    raw_has_more = completion.get("hasMore", False)
    if not isinstance(raw_has_more, bool):
        raise _shape_error("completion.hasMore must be a boolean")
    return MCPCompletionResult(
        values=tuple(raw_values),
        total=raw_total,
        has_more=raw_has_more,
    )


def normalize_tool_result(
    *,
    server_name: str,
    remote_name: str,
    result: dict[str, Any],
    output_schema: dict[str, Any],
    stderr_tail: str,
) -> dict[str, Any]:
    normalized_content = _object_list(result, "content")
    if any(not str(item.get("type", "")).strip() for item in normalized_content):
        raise _shape_error("content items must include type")
    if "isError" in result and not isinstance(result["isError"], bool):
        raise _shape_error("isError must be a boolean")
    text_parts = [
        str(item.get("text", "") or "").strip()
        for item in normalized_content
        if str(item.get("type", "") or "").strip().lower() == "text"
        and str(item.get("text", "") or "").strip()
    ]
    has_structured_content = "structuredContent" in result
    structured_content = result.get("structuredContent")
    if output_schema and has_structured_content:
        try:
            structured_content = validate_mcp_value(
                schema=output_schema,
                value=structured_content,
                value_path="structuredContent",
            )
        except MCPArgumentValidationError as exc:
            raise MCPProtocolError(
                f"MCP tool '{server_name}.{remote_name}' returned invalid structuredContent.",
                reason_code="mcp_output_schema_invalid",
            ) from exc
    content_text = "\n".join(text_parts).strip()
    if not content_text and has_structured_content:
        content_text = json.dumps(structured_content, sort_keys=True)

    if result.get("isError"):
        details = {"mcp_stderr_tail": stderr_tail} if stderr_tail else {}
        cancelled = isinstance(structured_content, dict) and bool(
            structured_content.get("cancelled")
        )
        raise MCPCallError(
            content_text
            or f"MCP tool '{server_name}.{remote_name}' returned an error.",
            reason_code="mcp_client_cancelled" if cancelled else "mcp_upstream_error",
            details=details,
        )

    return {
        "ok": True,
        "verified": True,
        "content": content_text,
        "source": "mcp",
        "data": {
            "mcp_server": server_name,
            "mcp_remote_tool_name": remote_name,
            "content_items": normalized_content,
            "structured_content": structured_content,
            "structured_content_present": has_structured_content,
            "output_schema": output_schema,
        },
    }


def normalize_prompt_result(
    *, server_name: str, remote_name: str, result: dict[str, Any]
) -> dict[str, Any]:
    normalized_messages = _object_list(result, "messages")
    if any(
        str(item.get("role", "")).strip() not in {"user", "assistant"}
        or "content" not in item
        for item in normalized_messages
    ):
        raise _shape_error("messages items must include role and content")
    text_parts = [
        text
        for item in normalized_messages
        for text in _collect_text_fragments(item.get("content"))
    ]
    description = str(result.get("description", "") or "").strip()
    return {
        "ok": True,
        "verified": True,
        "content": "\n".join(text_parts).strip() or description,
        "source": "mcp",
        "data": {
            "mcp_server": server_name,
            "mcp_remote_prompt_name": remote_name,
            "messages": normalized_messages,
            "description": description,
        },
    }


def normalize_resource_result(
    *, server_name: str, resource_uri: str, result: dict[str, Any]
) -> dict[str, Any]:
    normalized_contents = _object_list(result, "contents")
    if any(
        not str(item.get("uri", "")).strip() or not ({"text", "blob"} & item.keys())
        for item in normalized_contents
    ):
        raise _shape_error("contents items must include uri and text or blob")
    text_parts = [
        str(item.get("text", "") or "").strip()
        for item in normalized_contents
        if str(item.get("text", "") or "").strip()
    ]
    return {
        "ok": True,
        "verified": True,
        "content": "\n".join(text_parts).strip(),
        "source": "mcp",
        "data": {
            "mcp_server": server_name,
            "mcp_resource_uri": resource_uri,
            "contents": normalized_contents,
        },
    }


def _collect_text_fragments(content: Any) -> list[str]:
    if isinstance(content, str):
        text = content.strip()
        return [text] if text else []
    if isinstance(content, dict):
        text = str(content.get("text", "") or "").strip()
        if text:
            return [text]
        return [
            part
            for value in content.values()
            for part in _collect_text_fragments(value)
        ]
    if isinstance(content, list):
        return [part for item in content for part in _collect_text_fragments(item)]
    return []


def _object_list(result: dict[str, Any], key: str) -> list[dict[str, Any]]:
    raw = result.get(key)
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise _shape_error(f"{key} must be an array of objects")
    return [dict(item) for item in raw]


def _shape_error(message: str) -> MCPProtocolError:
    return MCPProtocolError(
        f"Malformed MCP result: {message}.",
        reason_code="mcp_result_shape_invalid",
    )


__all__ = [
    "MCPCallError",
    "MCPManagerError",
    "coerce_optional_int",
    "normalize_completion_result",
    "normalize_prompt_result",
    "normalize_resource_result",
    "normalize_tool_result",
]
