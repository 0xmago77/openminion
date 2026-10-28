from typing import Any

from openminion.modules.llm.providers import ProviderToolCall
from openminion.modules.policy.adapters.composition import (
    SEAM_API_TOOLS,
    build_default_composition_boundary_adapter,
)
from openminion.modules.tool.base import ToolExecutionContext
from openminion.modules.tool.contracts.schemas import TOOL_ERROR_CONFIRM_REQUIRED
from openminion.modules.task.constants import TASK_REASON_RESUME_EXPIRED_ONE_SHOT
from openminion.modules.task.scheduling.user_schedule import normalize_user_schedule
from openminion.modules.task.surface import (
    build_task_surface,
    resolve_task_surface_source,
)


class TaskControlOperationError(RuntimeError):
    def __init__(self, code: str, message: str, details: dict[str, Any]) -> None:
        self.code = code
        self.details = details
        super().__init__(message)

    @property
    def is_forbidden(self) -> bool:
        return self.code in {TOOL_ERROR_CONFIRM_REQUIRED, "POLICY_DENIED"}

    @property
    def response_code(self) -> str:
        reason = str(self.details.get("reason_code") or "")
        return reason if reason == TASK_REASON_RESUME_EXPIRED_ONE_SHOT else self.code


def execute_task_control(
    *,
    runtime: Any,
    tool_name: str,
    arguments: dict[str, object],
    agent_id: str,
    session_id: str,
    request_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    batch = runtime.tools.execute_calls(
        [
            ProviderToolCall(
                name=tool_name,
                arguments=arguments,
                id=request_id,
                source="api.tasks",
            )
        ],
        context=ToolExecutionContext(
            channel="api",
            target="tasks",
            session_id=session_id or "tasks",
            metadata={
                "agent_id": agent_id,
                "trace_id": request_id,
                "origin": "api.tasks",
            },
            task_manager=resolve_task_surface_source(runtime),
            scheduler_readiness=runtime.scheduler_readiness,
            confirm=confirm,
            blast_radius_adapter=build_default_composition_boundary_adapter(
                seam_id=SEAM_API_TOOLS,
            ),
        ),
    )
    result = batch.results[0] if batch.results else None
    if result is None:
        raise TaskControlOperationError(
            "EXEC_ERROR", "task control produced no result", {}
        )
    if not result.ok:
        data = dict(result.data or {})
        details = data.get("details")
        raise TaskControlOperationError(
            str(data.get("error_code") or "EXEC_ERROR"),
            str(result.error or "task control failed"),
            dict(details) if isinstance(details, dict) else data,
        )
    payload = dict(result.data or {})
    if tool_name in {"task.pause", "task.resume", "task.cancel"}:
        task_id = str(arguments["task_id"])
        payload = {
            **payload,
            "action": tool_name.removeprefix("task."),
            "task": build_task_surface(
                resolve_task_surface_source(runtime),
                agent_id=agent_id,
                session_id=session_id,
            ).show_task(task_id),
        }
    return payload


def create_task(
    *,
    runtime: Any,
    body: dict[str, object] | None,
    agent_id: str,
    request_id: str,
    session_id: str = "",
) -> dict[str, Any]:
    if body is None:
        raise ValueError("JSON request body is required")
    unknown_fields = sorted(set(body) - {"instruction", "schedule", "name"})
    if unknown_fields:
        raise ValueError(f"unknown task fields: {', '.join(unknown_fields)}")
    instruction = str(body.get("instruction") or "").strip()
    schedule = body.get("schedule")
    if not instruction:
        raise ValueError("instruction is required")
    if not isinstance(schedule, dict):
        raise ValueError("schedule is required")
    arguments: dict[str, object] = {
        "instruction": instruction,
        "schedule": normalize_user_schedule(schedule),
    }
    name = str(body.get("name") or "").strip()
    if name:
        arguments["name"] = name
    created = execute_task_control(
        runtime=runtime,
        tool_name="task.schedule",
        arguments=arguments,
        agent_id=agent_id,
        session_id=session_id,
        request_id=request_id,
    )
    task_id = str(created.get("task_id") or "")
    owner = resolve_task_surface_source(runtime)
    return {
        "ok": True,
        "task": build_task_surface(
            owner,
            agent_id=agent_id,
            session_id=session_id,
        ).show_task(task_id),
        "deduped": bool(created["deduped"]),
        "job_id": task_id,
        "scheduler": dict(created.get("scheduler") or {}),
    }
