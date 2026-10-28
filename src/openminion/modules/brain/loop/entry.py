from dataclasses import dataclass
from typing import Any, Literal, cast

from openminion.modules.brain.constants import (
    BRAIN_ACT_PROFILE_CODING,
    BRAIN_ACT_PROFILE_GENERAL,
    BRAIN_EXECUTION_TARGET_DELEGATED,
)
from openminion.modules.brain.loop.adaptive import ACT_ADAPTIVE_ALLOWED_TOOLS
from openminion.modules.brain.loop.services import runtime_allows_tool
from openminion.modules.brain.loop.strategies.coding.contracts import (
    CODING_ALLOWED_TOOLS,
)
from openminion.modules.brain.loop.tools.runtime import build_runtime_tool_specs
from openminion.modules.brain.tools.schema import collect_runtime_tool_names
from openminion.modules.brain.loop.tools.shortlisting import build_tool_request_spec
from openminion.modules.brain.loop.tools.plan_control import build_plan_tool_spec
from openminion.modules.brain.loop.tools.review_control import build_review_tool_spec
from openminion.modules.brain.schemas.readiness import ProjectHandoff
from openminion.modules.llm.schemas import ToolSpec

ENTRY_CLARIFY_TOOL_NAME = "clarify"
ENTRY_CODING_TOOL_NAME = "coding"
ENTRY_DECOMPOSE_TOOL_NAME = "decompose"
ENTRY_RESEARCH_TOOL_NAME = "research"
ENTRY_RESPOND_TOOL_NAME = "respond"
EntryPath = Literal["act", "respond", "clarify"]


@dataclass(frozen=True, slots=True)
class EntryPathDetection:
    path: EntryPath
    response_text: str
    clarify_question: str
    tool_call_names: tuple[str, ...]


def clarify_tool_spec() -> ToolSpec:
    return ToolSpec(
        name=ENTRY_CLARIFY_TOOL_NAME,
        description=("Ask only if blocked and no tool or documented default helps."),
        input_schema={
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The exact clarifying question to ask the user.",
                }
            },
            "required": ["question"],
            "additionalProperties": False,
        },
    )


def decompose_tool_spec() -> ToolSpec:
    return ToolSpec(
        name=ENTRY_DECOMPOSE_TOOL_NAME,
        description=(
            "Use independent subtasks for separate work, not a "
            "single deep-research thread or evidence pass."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "subtasks": {
                    "type": "array",
                    "description": (
                        "Independent model-authored subtasks; empty only to decline "
                        "decomposition."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Stable subtask id.",
                            },
                            "description": {
                                "type": "string",
                                "description": "Subtask description.",
                            },
                            "inputs": {
                                "type": "object",
                                "description": "Optional structured inputs.",
                                "additionalProperties": True,
                            },
                            "depends_on": {
                                "type": "array",
                                "description": "Prerequisite subtask ids.",
                                "items": {"type": "string"},
                            },
                            "suggested_mode": {
                                "type": "string",
                                "description": "Optional execution-mode hint.",
                            },
                            "priority": {
                                "type": "integer",
                                "description": "Optional priority hint.",
                            },
                        },
                        "required": ["id", "description"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["subtasks"],
            "additionalProperties": False,
        },
    )


def _project_handoff_input_schema() -> dict[str, Any]:
    handoff_schema = cast(dict[str, Any], ProjectHandoff.model_json_schema())
    properties = handoff_schema["properties"]
    properties.pop("repository")
    handoff_schema.pop("title", None)
    for field_schema in properties.values():
        field_schema.pop("title", None)
        field_schema.pop("default", None)
    for field_name in ("max_iterations", "max_wall_clock_ms", "max_tool_calls"):
        field_schema = properties[field_name]
        description = field_schema.get("description")
        choices = field_schema.pop("anyOf")
        integer_schema = next(
            choice for choice in choices if choice.get("type") == "integer"
        )
        field_schema.clear()
        field_schema.update(integer_schema)
        field_schema["description"] = description
    properties["user_request_quote"] = {
        "type": "string",
        "minLength": 1,
        "description": (
            "Exact request words that explicitly ask for durable, background, or "
            "restart-persistent work."
        ),
    }
    properties["verification_commands"]["minItems"] = 1
    properties["max_iterations"].pop("exclusiveMinimum", None)
    properties["max_iterations"]["minimum"] = 2
    handoff_schema["required"].extend(
        (
            "verification_commands",
            "verification_domain",
            "user_request_quote",
            "max_iterations",
        )
    )
    return handoff_schema


def _project_entry_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "project_handoff": _project_handoff_input_schema(),
            "sub_intents": {
                "type": "array",
                "description": "Required and nonempty with project_handoff.",
                "items": {"type": "string", "minLength": 1},
                "minItems": 1,
            },
        },
        "additionalProperties": False,
    }


def coding_tool_spec() -> ToolSpec:
    return ToolSpec(
        name=ENTRY_CODING_TOOL_NAME,
        description=(
            "dedicated coding loop; tests; final verification. Use foreground loop; "
            "project_handoff and sub_intents only for explicit durable, background, "
            "or restart-persistent requests."
        ),
        input_schema=_project_entry_input_schema(),
    )


def research_tool_spec() -> ToolSpec:
    return ToolSpec(
        name=ENTRY_RESEARCH_TOOL_NAME,
        description=(
            "iterative research loop; multiple searches; final synthesis. Use general "
            "foreground tools to produce code or files. Use project_handoff only for "
            "explicit durable, background, or restart-persistent work requests."
        ),
        input_schema=_project_entry_input_schema(),
    )


def respond_tool_spec() -> ToolSpec:
    return ToolSpec(
        name=ENTRY_RESPOND_TOOL_NAME,
        description=(
            "Return the complete answer with typed freshness when no tool or "
            "clarification is needed."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "answer": {
                    "type": "string",
                    "description": "The complete truthful answer to show the user.",
                },
                "freshness": _freshness_input_schema(),
            },
            "required": ["answer", "freshness"],
            "additionalProperties": False,
        },
    )


def _freshness_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "enum": [
                    "general",
                    "finance",
                    "news",
                    "weather",
                    "regulation",
                    "shopping",
                    "sports",
                    "other",
                ],
            },
            "time_sensitive": {"type": "boolean"},
            "needs_live_data": {"type": "boolean"},
            "needs_sources": {"type": "boolean"},
            "needs_exact_date": {"type": "boolean"},
            "answer_mode": {
                "type": "string",
                "enum": ["local_only", "browse_then_answer"],
            },
        },
        "required": [
            "domain",
            "time_sensitive",
            "needs_live_data",
            "needs_sources",
            "needs_exact_date",
            "answer_mode",
        ],
        "additionalProperties": False,
    }


def _with_freshness_contract(spec: ToolSpec) -> ToolSpec:
    schema = dict(spec.input_schema or {})
    properties = dict(schema.get("properties") or {})
    properties["freshness"] = _freshness_input_schema()
    required = [str(item) for item in schema.get("required", [])]
    if "freshness" not in required:
        required.append("freshness")
    schema.update(
        {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }
    )
    return spec.model_copy(update={"input_schema": schema})


def extract_response_text(response: Any) -> str:
    text = str(getattr(response, "output_text", "") or "").strip()
    if text:
        return text
    assistant_messages = list(getattr(response, "assistant_messages", []) or [])
    for message in reversed(assistant_messages):
        content = str(getattr(message, "content", "") or "").strip()
        if content:
            return content
    return ""


def detect_entry_path(response: Any) -> EntryPathDetection:
    tool_calls = list(getattr(response, "tool_calls", []) or [])
    tool_call_names = tuple(
        str(getattr(call, "name", "") or "").strip() for call in tool_calls
    )
    response_text = extract_response_text(response)
    clarify_question = ""
    for call in tool_calls:
        call_name = str(getattr(call, "name", "") or "").strip()
        arguments = getattr(call, "arguments", {}) or {}
        if call_name == ENTRY_RESPOND_TOOL_NAME:
            answer = (
                str(arguments.get("answer", "") or "").strip()
                if isinstance(arguments, dict)
                else ""
            )
            return EntryPathDetection(
                path="respond",
                response_text=answer or response_text,
                clarify_question="",
                tool_call_names=tool_call_names,
            )
        if call_name != ENTRY_CLARIFY_TOOL_NAME:
            continue
        if isinstance(arguments, dict):
            clarify_question = str(arguments.get("question", "") or "").strip()
        if not clarify_question:
            clarify_question = response_text
        return EntryPathDetection(
            path="clarify",
            response_text=response_text,
            clarify_question=clarify_question,
            tool_call_names=tool_call_names,
        )
    if tool_call_names:
        return EntryPathDetection(
            path="act",
            response_text=response_text,
            clarify_question="",
            tool_call_names=tool_call_names,
        )
    return EntryPathDetection(
        path="respond",
        response_text=response_text,
        clarify_question="",
        tool_call_names=tool_call_names,
    )


def entry_supports_seed_response(
    *,
    act_profile: str,
    execution_target_kind: str,
) -> bool:
    normalized_profile = str(act_profile or "").strip().lower()
    normalized_target = str(execution_target_kind or "").strip().lower()
    if normalized_target == BRAIN_EXECUTION_TARGET_DELEGATED:
        return False
    return normalized_profile in {
        BRAIN_ACT_PROFILE_GENERAL,
        BRAIN_ACT_PROFILE_CODING,
    }


def build_entry_tool_specs(
    runner: Any | None,
    *,
    act_profile: str,
    execution_target_kind: str,
    include_control_tools: bool = True,
    metadata: dict[str, Any] | None = None,
) -> tuple[list[ToolSpec], bool]:
    normalized_profile = str(act_profile or "").strip().lower()
    normalized_target = str(execution_target_kind or "").strip().lower()
    supports_seed = entry_supports_seed_response(
        act_profile=normalized_profile,
        execution_target_kind=normalized_target,
    )
    requestable_specs = build_entry_requestable_tool_specs(
        runner,
        act_profile=normalized_profile,
        execution_target_kind=normalized_target,
        metadata=metadata,
    )
    tool_specs: list[ToolSpec] = []
    if requestable_specs:
        if runtime_allows_tool(runner, "tool.request"):
            tool_specs.append(_with_freshness_contract(build_tool_request_spec()))
        else:
            tool_specs.extend(requestable_specs)
    if include_control_tools:
        control_specs = [
            respond_tool_spec(),
            _with_freshness_contract(coding_tool_spec()),
            _with_freshness_contract(build_plan_tool_spec()),
            _with_freshness_contract(research_tool_spec()),
            _with_freshness_contract(decompose_tool_spec()),
            _with_freshness_contract(clarify_tool_spec()),
            _with_freshness_contract(build_review_tool_spec()),
        ]
        tool_specs.extend(
            spec for spec in control_specs if runtime_allows_tool(runner, spec.name)
        )
    return tool_specs, supports_seed


def build_entry_requestable_tool_specs(
    runner: Any | None,
    *,
    act_profile: str,
    execution_target_kind: str,
    metadata: dict[str, Any] | None = None,
) -> list[ToolSpec]:
    if not entry_supports_seed_response(
        act_profile=act_profile,
        execution_target_kind=execution_target_kind,
    ):
        return []
    allowed_tools = (
        CODING_ALLOWED_TOOLS
        if str(act_profile or "").strip().lower() == BRAIN_ACT_PROFILE_CODING
        else ACT_ADAPTIVE_ALLOWED_TOOLS
    )
    if runner is not None:
        allowed_tools = frozenset(
            {*allowed_tools, *collect_runtime_tool_names(runner, metadata=metadata)}
        )
    return build_runtime_tool_specs(
        runner, allowed_tools=allowed_tools, metadata=metadata
    )


def _with_forced_runtime_tool_specs(
    runner: Any,
    tool_specs: list[Any],
    forced_tools: list[str] | None,
    *,
    metadata: dict[str, Any] | None = None,
) -> list[Any]:
    forced = {str(name or "").strip() for name in list(forced_tools or [])}
    forced.discard("")
    if not forced:
        return tool_specs
    existing = {
        str(getattr(spec, "name", "") or "").strip()
        for spec in tool_specs
        if str(getattr(spec, "name", "") or "").strip()
    }
    missing = forced - existing
    if not missing:
        return tool_specs
    dynamic_specs = build_runtime_tool_specs(
        runner, allowed_tools=frozenset(missing), metadata=metadata
    )
    return [*tool_specs, *dynamic_specs]
