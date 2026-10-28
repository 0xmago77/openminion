from collections.abc import Mapping
from typing import Any

from openminion.modules.task import TaskManager
from openminion.modules.task.surface import (
    supports_generic_lifecycle_control,
    task_lifecycle_record_payload,
)

from .scheduled_task.runtime import _text


def task_list_policy(ctx: Any) -> tuple[bool, bool]:
    raw = getattr(ctx.policy, "raw", {}) or {}
    if not isinstance(raw, Mapping):
        return False, False
    metadata = raw.get("context_metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}

    def enabled(value: Any) -> bool:
        return _text(value).lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    return (
        enabled(raw.get("task_list_allow_cross_agent"))
        or enabled(metadata.get("task_list_allow_cross_agent")),
        enabled(raw.get("task_list_include_unowned"))
        or enabled(metadata.get("task_list_include_unowned")),
    )


def lifecycle_task_payload(
    manager: TaskManager,
    *,
    task_id: str,
    runs_limit: int = 5,
) -> dict[str, Any] | None:
    record = manager.get_task(task_id)
    if record is None or not supports_generic_lifecycle_control(record):
        return None
    task = task_lifecycle_record_payload(
        manager,
        record,
        runs_limit=runs_limit,
    )
    return {
        **task,
        "task_id": task_id,
        "name": task.get("title"),
        "runs": list(task.get("recent_runs") or []),
    }


def list_lifecycle_task_payloads(
    manager: TaskManager,
    *,
    agent_id: str,
    limit: int,
    allow_cross_agent: bool = False,
    include_unowned: bool = False,
) -> list[dict[str, Any]]:
    records = manager.lifecycle_repository.list(
        agent_id=None if allow_cross_agent else agent_id,
        include_unowned=include_unowned,
        limit=1000,
    )
    return [
        payload
        for record in records
        if (include_unowned or getattr(record, "agent_id", None) is not None)
        if manager.get_scheduled_job(record.task_id) is None
        and (
            payload := lifecycle_task_payload(
                manager,
                task_id=record.task_id,
            )
        )
        is not None
    ][:limit]


def restrict_task_actions_to_owner(
    tasks: list[dict[str, Any]],
    *,
    agent_id: str,
) -> list[dict[str, Any]]:
    for task in tasks:
        if str(task.get("agent_id") or "").strip() != agent_id:
            task["valid_actions"] = []
    return tasks


def append_lifecycle_task_payloads(
    manager: TaskManager,
    *,
    tasks: list[dict[str, Any]],
    agent_id: str,
    limit: int,
    allow_cross_agent: bool = False,
    include_unowned: bool = False,
) -> list[dict[str, Any]]:
    scheduled_ids = {str(task.get("task_id") or "") for task in tasks}
    tasks.extend(
        task
        for task in list_lifecycle_task_payloads(
            manager,
            agent_id=agent_id,
            limit=limit,
            allow_cross_agent=allow_cross_agent,
            include_unowned=include_unowned,
        )
        if str(task.get("task_id") or "") not in scheduled_ids
    )
    tasks.sort(key=lambda task: str(task.get("created_at") or ""), reverse=True)
    return tasks[:limit]


def lifecycle_task_result(
    manager: TaskManager,
    *,
    task_id: str,
    runs_limit: int,
) -> dict[str, Any]:
    return {
        "ok": True,
        "task": lifecycle_task_payload(
            manager,
            task_id=task_id,
            runs_limit=runs_limit,
        ),
        "runs_limit": runs_limit,
    }


__all__ = [
    "append_lifecycle_task_payloads",
    "lifecycle_task_payload",
    "lifecycle_task_result",
    "list_lifecycle_task_payloads",
    "restrict_task_actions_to_owner",
    "task_list_policy",
]
