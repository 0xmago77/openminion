"""Gemini's OpenAI-compatible endpoint receives one merged system message.

The endpoint appears to read only the last system message, so the request
compatibility profile for it reuses `collapse_system_messages`. These tests
assert the outbound payloads built from real configurations and real brain
control requests.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from openminion.base.config.runtime.profile import build_runtime_config
from openminion.modules.brain.adapters.a2a import LocalA2AAdapter
from openminion.modules.brain.adapters.factory import create_context_adapter
from openminion.modules.brain.adapters.llm import LlmctlAdapter
from openminion.modules.brain.adapters.memory import LocalMemoryAdapter
from openminion.modules.brain.adapters.policy import LocalPolicyAdapter
from openminion.modules.brain.adapters.session import LocalSessionStore
from openminion.modules.brain.adapters.tool import LocalToolAdapter
from openminion.modules.brain.execution.runtime.memory.afe import (
    extract_user_message_candidates,
)
from openminion.modules.brain.loop.tools.iteration.helpers import (
    _tool_result_payload_from_action,
)
from openminion.modules.brain.runner import BrainRunner, RunnerOptions
from openminion.modules.brain.schemas import (
    ActionResult,
    AgentBudgets,
    AgentDefaults,
    AgentProfile,
    LLMProfiles,
)
from openminion.modules.llm.config import resolve_provider_identity_translation
from openminion.modules.llm.providers.factory import (
    RuntimeLLMHandle,
    build_runtime_llm_handle,
)
from openminion.modules.llm.providers.openai.request_compatibility import (
    OpenAIRequestCompatProfile,
    resolve_openai_request_compat,
)
from openminion.modules.llm.schemas import LLMRequest, LLMResponse
from openminion.modules.llm.setup_catalog import get_setup_preset
from openminion.services.bootstrap.provider_setup import (
    ProviderSetupRequest,
    build_provider_setup,
)

_ADAPTER = "openminion.modules.llm.providers.openai.adapter"
_MODEL = "gemini-3.1-flash-lite"
_GEMINI_CHAT_URL = (
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
)
_GATEWAY_BASE_URL = "https://llm-gateway.example.test/v1"
_TOOL_OUTPUT = "order A-104: ready for pickup, pickup code ZEBRA-42"
_CANDIDATE = "Order A-104 is ready for pickup. Your pickup code is ZEBRA-42."
_CONTRACT_PREFIX = "Tool-calling contract:"

# Configurations that resolve to Gemini's endpoint: the preset, a custom-named
# OpenAI-compatible connection, and a config whose identity is derived from
# its base URL because none is stored.
_GEMINI_SETUPS = {
    "gemini-preset": {"preset_id": "gemini", "agent_id": "gemini"},
    "custom-name": {
        "preset_id": "custom-openai-compatible",
        "agent_id": "research-bot",
        "connection_id": "google-ai-studio",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
    },
    "identity-from-base-url": {
        "preset_id": "gemini",
        "agent_id": "gemini",
        "drop_stored_identity": True,
    },
}
# The same Gemini model behind a non-Google OpenAI-compatible gateway.
_GATEWAY_SETUP = {
    "preset_id": "custom-openai-compatible",
    "agent_id": "gateway",
    "base_url": _GATEWAY_BASE_URL,
}


class _Wire:
    """Captures outbound chat-completions payloads and answers them."""

    def __init__(self, replies: dict[str, dict[str, Any]] | None = None) -> None:
        self.replies = dict(replies or {})
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.streams: list[tuple[str, dict[str, Any]]] = []

    def post(self, **kwargs: Any) -> dict[str, Any]:
        payload = copy.deepcopy(kwargs["payload"])
        self.posts.append((kwargs["url"], payload))
        title = _schema_title(payload)
        if title in self.replies:
            message: dict[str, Any] = {
                "content": "",
                "tool_calls": [
                    {
                        "id": f"call-{len(self.posts)}",
                        "type": "function",
                        "function": {
                            "name": "submit_output",
                            "arguments": json.dumps(self.replies[title]),
                        },
                    }
                ],
            }
            finish_reason = "tool_calls"
        else:
            message = {"content": _CANDIDATE}
            finish_reason = "stop"
        return {
            "model": payload["model"],
            "choices": [{"finish_reason": finish_reason, "message": message}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        }

    def stream(self, **kwargs: Any) -> Iterator[str]:
        self.streams.append((kwargs["url"], copy.deepcopy(kwargs["payload"])))
        yield 'data: {"choices":[{"delta":{"content":"ok"}}]}'
        yield "data: [DONE]"

    @contextmanager
    def installed(self) -> Iterator[_Wire]:
        with (
            patch(f"{_ADAPTER}._http_json_post", side_effect=self.post),
            patch(f"{_ADAPTER}.iter_sse_post_lines", side_effect=self.stream),
        ):
            yield self


class _PairedClient:
    """Brain LLM client: sends each request through Gemini and the reference."""

    def __init__(
        self, gemini: RuntimeLLMHandle, reference: RuntimeLLMHandle, wire: _Wire
    ) -> None:
        self.gemini = gemini
        self.reference = reference
        self.wire = wire
        self.exchanges: list[tuple[LLMRequest, dict[str, Any], dict[str, Any]]] = []

    def call(self, request: LLMRequest) -> LLMResponse:
        assert self.reference.client.call_sync(request=request).ok
        reference_body = self.wire.posts[-1][1]
        response = self.gemini.client.call_sync(request=request)
        self.exchanges.append((request, reference_body, self.wire.posts[-1][1]))
        return response


def _schema_title(payload: dict[str, Any]) -> str:
    tools = payload.get("tools") or []
    if not tools:
        return ""
    return str(tools[0]["function"]["parameters"].get("title", ""))


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    return "\n".join(
        part["text"].strip() for part in content if part.get("type") == "text"
    )


def _runtime_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    preset_id: str,
    agent_id: str,
    model: str = _MODEL,
    base_url: str = "",
    connection_id: str = "",
    drop_stored_identity: bool = False,
) -> RuntimeLLMHandle:
    credential_env = get_setup_preset(preset_id).credential_env
    monkeypatch.setenv(credential_env, "fixture-key")
    home = tmp_path / agent_id
    result = build_provider_setup(
        ProviderSetupRequest(
            preset_id=preset_id,
            agent_id=agent_id,
            model=model,
            base_url=base_url,
            connection_id=connection_id,
            config_path=str(home / ".openminion" / "agents.json"),
            home_root=home,
            data_root=home / ".openminion",
            env={credential_env: "fixture-key"},
        )
    )
    runtime_config = build_runtime_config(result.config, agent_id=agent_id)
    if drop_stored_identity:
        runtime_config.providers.openai.provider_identity = {}
    return build_runtime_llm_handle(runtime_config, logging.getLogger(__name__))


def _schema_only_request() -> LLMRequest:
    return LLMRequest.model_validate(
        {
            "messages": [
                {"role": "system", "content": "Primary system context."},
                {"role": "user", "content": "Check order A-104"},
            ],
            "tools": [
                {
                    "name": "submit_output",
                    "description": "return structured output",
                    "input_schema": {"type": "object", "title": "ClosureJudgment"},
                }
            ],
            "tool_choice": {
                "type": "function",
                "function": {"name": "submit_output"},
            },
        }
    )


def _assert_one_merged_system_message(
    gemini_body: dict[str, Any], reference_body: dict[str, Any]
) -> str:
    """Gemini body equals the reference body with its system messages merged."""
    reference_messages = reference_body["messages"]
    system_texts = [
        _text(message["content"])
        for message in reference_messages
        if message["role"] == "system"
    ]
    assert len(system_texts) >= 2
    assert gemini_body["messages"] == [
        {"role": "system", "content": "\n\n".join(system_texts)},
        *[message for message in reference_messages if message["role"] != "system"],
    ]
    assert {key: value for key, value in gemini_body.items() if key != "messages"} == {
        key: value for key, value in reference_body.items() if key != "messages"
    }
    return str(gemini_body["messages"][0]["content"])


def test_gemini_endpoint_identity_selects_collapse_only_profile() -> None:
    identity = resolve_provider_identity_translation(
        "openai",
        model=_MODEL,
        base_url=get_setup_preset("gemini").default_base_url,
    )

    profile = resolve_openai_request_compat(provider_identity=identity)

    assert identity == {
        "transport_adapter": "openai_chat",
        "wire_protocol_family": "openai_chat_completions",
        "service_vendor": "gemini",
        "model_family": "gemini",
    }
    assert dataclasses.asdict(profile) == {
        **dataclasses.asdict(OpenAIRequestCompatProfile()),
        "profile_id": "gemini_openai_compat",
        "collapse_system_messages": True,
    }


@pytest.mark.parametrize(
    "provider_identity",
    [
        pytest.param(
            resolve_provider_identity_translation(
                "openai", model=_MODEL, base_url=_GATEWAY_BASE_URL
            ),
            id="gemini-model-behind-gateway",
        ),
        pytest.param(
            resolve_provider_identity_translation(
                "openai",
                model=_MODEL,
                base_url="https://generativelanguage.googleapis.com.example.test/v1",
            ),
            id="lookalike-host",
        ),
        pytest.param(
            resolve_provider_identity_translation(
                "openrouter", model="google/gemini-3.1-flash-lite"
            ),
            id="openrouter-gemini-model",
        ),
        pytest.param(
            {
                "transport_adapter": "anthropic_messages",
                "wire_protocol_family": "openai_chat_completions",
                "service_vendor": "gemini",
                "model_family": "gemini",
            },
            id="other-transport",
        ),
        pytest.param(
            {
                "transport_adapter": "openai_chat",
                "wire_protocol_family": "openai_responses",
                "service_vendor": "gemini",
                "model_family": "gemini",
            },
            id="other-wire-protocol",
        ),
        pytest.param(None, id="no-identity"),
    ],
)
def test_gemini_profile_requires_the_normalized_endpoint_identity(
    provider_identity: dict[str, str] | None,
) -> None:
    profile = resolve_openai_request_compat(provider_identity=provider_identity)

    assert profile == OpenAIRequestCompatProfile()


@pytest.mark.parametrize("setup", _GEMINI_SETUPS.values(), ids=_GEMINI_SETUPS)
def test_gemini_configurations_send_one_system_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setup: dict[str, Any]
) -> None:
    gemini = _runtime_handle(tmp_path, monkeypatch, **setup)
    reference = _runtime_handle(tmp_path, monkeypatch, **_GATEWAY_SETUP)
    wire = _Wire(replies={"ClosureJudgment": {"next_action": "close"}})
    try:
        with wire.installed():
            reference_response = reference.client.call_sync(
                request=_schema_only_request()
            )
            gemini_response = gemini.client.call_sync(request=_schema_only_request())
    finally:
        gemini.close()
        reference.close()

    assert reference_response.ok and gemini_response.ok
    assert [url for url, _body in wire.posts] == [
        f"{_GATEWAY_BASE_URL}/chat/completions",
        _GEMINI_CHAT_URL,
    ]
    assert gemini_response.telemetry["normalization"]["request_compat_profile"] == (
        "gemini_openai_compat"
    )
    merged = _assert_one_merged_system_message(wire.posts[1][1], wire.posts[0][1])
    assert merged.startswith(f"Primary system context.\n\n{_CONTRACT_PREFIX}")
    assert wire.posts[1][1]["messages"][1] == {
        "role": "user",
        "content": "Check order A-104",
    }
    assert gemini_response.tool_calls[0].arguments == {"next_action": "close"}


def test_gemini_judge_repair_and_reflect_requests_carry_their_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gemini = _runtime_handle(tmp_path, monkeypatch, **_GEMINI_SETUPS["gemini-preset"])
    reference = _runtime_handle(tmp_path, monkeypatch, **_GATEWAY_SETUP)
    wire = _Wire(
        replies={
            "UserMessageCandidateReport": {"items": []},
            "ClosureJudgment": {
                "satisfied": True,
                "reason": "lookup_order returned the order status",
                "next_action": "close",
            },
            "_ClosureFinalAnswerRepair": {"final_answer": _CANDIDATE},
        }
    )
    client = _PairedClient(gemini, reference, wire)
    session = LocalSessionStore(tmp_path / "brain" / "sessions")
    context_api = create_context_adapter(mode="auto", session_store=session)
    runner = BrainRunner(
        profile=AgentProfile(
            agent_id="gemini-agent",
            role="general",
            llm_profiles=LLMProfiles(
                decide_model=_MODEL,
                plan_model=_MODEL,
                act_model=None,
                reflect_model=_MODEL,
                summarize_model=_MODEL,
            ),
            budgets=AgentBudgets(
                max_ticks_per_user_turn=3,
                max_tool_calls=2,
                max_a2a_calls=1,
                max_total_llm_tokens=4000,
                max_elapsed_ms=10000,
            ),
            defaults=AgentDefaults(),
        ),
        session_api=session,
        context_api=context_api,
        llm_api=LlmctlAdapter(client),
        tool_api=LocalToolAdapter(),
        a2a_api=LocalA2AAdapter(),
        memory_api=LocalMemoryAdapter(tmp_path / "brain" / "memory"),
        policy_api=LocalPolicyAdapter(),
        options=RunnerOptions(metactl_enabled=False),
    )
    state = runner._load_or_init_state("gemini-system-messages")
    state.goal = "Check order A-104"
    tool_result = _tool_result_payload_from_action(
        call_id="call-lookup-order",
        tool_name="lookup_order",
        action_result=ActionResult(
            command_id="call-lookup-order",
            status="success",
            summary="Tool executed successfully",
            outputs={"data": _TOOL_OUTPUT},
        ),
    )
    try:
        with wire.installed():
            report = extract_user_message_candidates(
                runner,
                state=state,
                user_message="Check order A-104 and quote the pickup code",
                logger=MagicMock(),
            )
            judgment = runner._evaluate_turn_closure(
                state=state,
                action_result=ActionResult(
                    command_id="cmd-act-loop",
                    status="success",
                    summary=_CANDIDATE,
                    outputs={"tool_results": [tool_result]},
                ),
                logger=MagicMock(),
                completion_reason="act_adaptive_final_text",
            )
    finally:
        context_api.close()
        gemini.close()
        reference.close()

    assert report == {"items": []}
    assert judgment.next_action == "close"
    assert judgment.final_answer == _CANDIDATE
    assert [
        _schema_title(gemini_body) for _r, _ref, gemini_body in client.exchanges
    ] == [
        "UserMessageCandidateReport",
        "ClosureJudgment",
        "_ClosureFinalAnswerRepair",
    ]
    for request, reference_body, gemini_body in client.exchanges:
        merged = _assert_one_merged_system_message(gemini_body, reference_body)
        request_system_texts = [
            message.content.strip()
            for message in request.messages
            if message.role == "system"
        ]
        contract = _text(reference_body["messages"][-2]["content"])
        assert reference_body["messages"][-1]["role"] == "user"
        assert contract.startswith(_CONTRACT_PREFIX)
        assert merged == "\n\n".join([*request_system_texts, contract])
        assert [
            _text(message["content"]) for message in gemini_body["messages"][1:]
        ] == [
            message.content.strip()
            for message in request.messages
            if message.role != "system"
        ]
    reflect, judge, repair = (
        str(gemini_body["messages"][0]["content"])
        for _request, _reference_body, gemini_body in client.exchanges
    )
    assert "purpose: reflect" in reflect
    assert "auto_fact_extraction_contract" in reflect
    for merged in (judge, repair):
        assert "[JUDGE CONTEXT]" in merged
        assert f"action_summary: {_CANDIDATE}" in merged
        assert _TOOL_OUTPUT in merged
        assert merged.index(_TOOL_OUTPUT) < merged.index(_CONTRACT_PREFIX)


def test_gemini_ordinary_tool_call_complete_and_stream_keep_turn_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    messages = [
        {"role": "system", "content": "Agent prompt: use lookup_order."},
        {"role": "user", "content": "Check order A-104"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-lookup",
                    "name": "lookup_order",
                    "arguments": {"order_id": "A-104"},
                }
            ],
        },
        {
            "role": "tool",
            "content": _TOOL_OUTPUT,
            "tool_call_id": "call-lookup",
            "tool_status": "success",
        },
        {"role": "system", "content": "Runtime note: answer in one sentence."},
    ]
    tools = [
        {
            "name": "lookup_order",
            "description": "Look up one order.",
            "input_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
            },
        }
    ]
    turns = [
        {"role": "user", "content": "Check order A-104"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-lookup",
                    "type": "function",
                    "function": {
                        "name": "lookup_order",
                        "arguments": '{"order_id": "A-104"}',
                    },
                }
            ],
        },
        {"role": "tool", "content": _TOOL_OUTPUT, "tool_call_id": "call-lookup"},
    ]
    gemini = _runtime_handle(tmp_path, monkeypatch, **_GEMINI_SETUPS["gemini-preset"])
    reference = _runtime_handle(tmp_path, monkeypatch, **_GATEWAY_SETUP)
    wire = _Wire()
    request = LLMRequest.model_validate(
        {"messages": messages, "tools": tools, "tool_choice": "auto"}
    )
    try:
        with wire.installed():
            for handle in (reference, gemini):
                assert handle.client.call_sync(request=request).output_text == (
                    _CANDIDATE
                )
                events = list(handle.client.stream(messages, tools, tool_choice="auto"))
                assert [event.type for event in events] == ["delta", "done"]
    finally:
        gemini.close()
        reference.close()

    (_, reference_complete), (_, gemini_complete) = wire.posts
    (_, reference_stream), (_, gemini_stream) = wire.streams
    contract = reference_complete["messages"][0]["content"]
    assert contract.startswith(_CONTRACT_PREFIX)
    assert reference_complete["messages"] == [
        {"role": "system", "content": contract},
        {"role": "system", "content": "Agent prompt: use lookup_order."},
        *turns,
        {"role": "system", "content": "Runtime note: answer in one sentence."},
    ]
    assert gemini_complete["messages"] == [
        {
            "role": "system",
            "content": (
                f"{contract}\n\nAgent prompt: use lookup_order.\n\n"
                "Runtime note: answer in one sentence."
            ),
        },
        *turns,
    ]
    _assert_one_merged_system_message(gemini_complete, reference_complete)
    assert gemini_complete["tool_choice"] == "auto"
    assert [tool["function"]["name"] for tool in gemini_complete["tools"]] == [
        "lookup_order"
    ]
    assert gemini_stream["messages"] == [
        {
            "role": "system",
            "content": (
                "Agent prompt: use lookup_order.\n\n"
                "Runtime note: answer in one sentence."
            ),
        },
        *turns,
    ]
    _assert_one_merged_system_message(gemini_stream, reference_stream)
    assert gemini_stream["stream"] is True


@pytest.mark.parametrize(
    ("setup", "expected_profile", "expected_roles"),
    [
        pytest.param(
            {
                "preset_id": "openai",
                "agent_id": "openai-agent",
                "model": "gpt-4.1-mini",
            },
            "openai_default",
            ["system", "system", "user"],
            id="openai",
        ),
        pytest.param(
            {
                "preset_id": "minimax",
                "agent_id": "minimax-agent",
                "model": "MiniMax-M2.7",
            },
            "minimax_openai_compat",
            ["system", "user"],
            id="minimax",
        ),
        pytest.param(
            {
                "preset_id": "cortensor-portal",
                "agent_id": "cortensor-agent",
                "model": "oss-20b",
            },
            "cortensor_portal",
            ["system", "system", "user"],
            id="cortensor-portal",
        ),
        pytest.param(
            _GATEWAY_SETUP,
            "openai_default",
            ["system", "system", "user"],
            id="gemini-model-behind-gateway",
        ),
    ],
)
def test_other_endpoints_keep_their_request_profiles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setup: dict[str, Any],
    expected_profile: str,
    expected_roles: list[str],
) -> None:
    handle = _runtime_handle(tmp_path, monkeypatch, **setup)
    wire = _Wire(replies={"ClosureJudgment": {"next_action": "close"}})
    try:
        with wire.installed():
            response = handle.client.call_sync(request=_schema_only_request())
    finally:
        handle.close()

    assert response.ok
    assert response.telemetry["normalization"]["request_compat_profile"] == (
        expected_profile
    )
    messages = wire.posts[0][1]["messages"]
    assert [message["role"] for message in messages] == expected_roles
    if expected_profile == "openai_default":
        assert messages[0] == {"role": "system", "content": "Primary system context."}
        assert messages[1]["content"].startswith(_CONTRACT_PREFIX)
