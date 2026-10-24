"""Run-status values of a runtime session event payload (#352).

The run-status readers in `openminion.modules.task.run` read a few values of
each event's payload. These are their reading rules, owned by the session
store so that storage can apply the same rules; `task/run/status.py` imports
them.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

RUN_STATES = frozenset(
    {
        "queued",
        "running",
        "waiting_tool",
        "responding",
        "completed",
        "failed",
        "cancelled",
    }
)
DEFAULT_RUN_STATE = "running"


def payload_text(payload: Mapping[str, Any], key: str) -> str:
    """Read a payload value as the readers do: `str(payload.get(key, "")).strip()`."""
    return str(payload.get(key, "")).strip()


def payload_id(payload: Mapping[str, Any], key: str) -> str:
    """Read a conversation or thread id; a false value (null, false, 0) is empty."""
    return str(payload.get(key, "") or "").strip()


def normalize_run_state(*, state: Any, source_event_type: str) -> str:
    candidate = str(state or "").strip().lower()
    if candidate in RUN_STATES:
        return candidate

    if source_event_type.startswith("run."):
        suffix = source_event_type.split(".", 1)[1].strip().lower()
        if suffix in RUN_STATES:
            return suffix
    return DEFAULT_RUN_STATE


def extract_event_error(payload: Mapping[str, Any]) -> str:
    raw_error = payload.get("error")
    return "" if raw_error is None else str(raw_error).strip()
