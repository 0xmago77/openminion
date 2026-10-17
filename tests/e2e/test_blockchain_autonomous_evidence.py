from __future__ import annotations

from copy import deepcopy
import json
import os
import re
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from tests.e2e.runners import (
    run_blockchain_autonomous_focus_minimax as focus_runner,
)
from tests.e2e.runners import run_blockchain_autonomous_local as autonomous_runner
from tests.e2e.runners import run_blockchain_debug_local_anvil as debug_runner
from tests.e2e.runners import run_blockchain_local_anvil as configured_runner
from tests.e2e.runners import run_blockchain_public_read as public_read_runner
from tests.e2e.runners import run_blockchain_testnet_write as testnet_runner
from tests.e2e.runners.run_blockchain_autonomous_local import PROMPT, _run

pytestmark = pytest.mark.e2e

_HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUBSTANTIVE_CALL_IDS = (
    "search",
    "fetch",
    "resolve",
    "inspect-read",
    "prepare",
    "send",
    "operation-status",
)


def _fail(message: str) -> None:
    raise ValueError(message)


def _tool_events(
    payload: dict,
) -> tuple[dict[str, tuple[int, dict]], dict[str, tuple[int, dict]]]:
    requested: dict[str, tuple[int, dict]] = {}
    completed: dict[str, tuple[int, dict]] = {}
    for index, event in enumerate(payload.get("events", ())):
        if not isinstance(event, dict):
            continue
        event_payload = event.get("payload")
        if not isinstance(event_payload, dict):
            continue
        call_id = str(event_payload.get("call_id", ""))
        if event.get("event_type") == "tool.call.requested":
            requested[call_id] = (index, event)
        elif event.get("event_type") == "tool.call.completed":
            completed[call_id] = (index, event)
    return requested, completed


def validate_blockchain_autonomous_evidence(payload: object) -> None:
    if not isinstance(payload, dict):
        _fail("blockchain evidence must be a structured object")
    if payload.get("schema_version") != "blockchain-autonomous-local-evidence-v1":
        _fail("blockchain evidence schema is missing")
    if not _HEX_COMMIT.fullmatch(str(payload.get("source_commit", ""))):
        _fail("source commit is missing")
    if payload.get("scenario_id") != "autonomous-local-anvil":
        _fail("blockchain evidence scenario is missing")
    if payload.get("terminal_result") != "completed":
        _fail("blockchain evidence terminal result is missing")
    if payload.get("prompt") != PROMPT or payload.get("hidden_context") != {}:
        _fail("the no-hints task boundary changed")
    route = payload.get("route")
    if route != {
        "act_profile": "general",
        "execution_target": "local",
        "handler": "ActLoopMode",
    }:
        _fail("the task did not use the current general act loop")

    executed = payload.get("executed_tools")
    if not isinstance(executed, list):
        _fail("executed tool evidence is missing")
    executed_names = {
        item.get("tool_name") for item in executed if isinstance(item, dict)
    }
    required_tools = {
        "web.search",
        "web.fetch",
        "blockchain.resolve_contract",
        "blockchain.inspect",
        "blockchain.prepare_transaction",
        "blockchain.send_transaction",
    }
    if not required_tools.issubset(executed_names):
        _fail("research and blockchain tool coverage is incomplete")
    resolver_call = next(
        item
        for item in executed
        if item.get("tool_name") == "blockchain.resolve_contract"
    )
    resources = resolver_call.get("arguments")
    if not isinstance(resources, dict):
        _fail("researched resolver inputs are missing")
    forbidden_hints = {
        str(resources.get("rpc_url", "")),
        str(resources.get("expected_chain_id", "")),
        str(resources.get("expected_genesis_hash", "")),
        str(resources.get("contract_address", "")),
        str(resources.get("explorer_contract_url", "")),
        "quote(uint256)",
        "swap((address,uint256,uint256))",
        "14",
        *required_tools,
    }
    if any(token and token in PROMPT for token in forbidden_hints):
        _fail("the task prompt contains a concrete discovery or answer hint")

    model_calls = payload.get("model_calls")
    if not isinstance(model_calls, list) or len(model_calls) < 2:
        _fail("model decision evidence is incomplete")
    if model_calls[0].get("tool_choice") != "none" or model_calls[0].get("tools") != []:
        _fail("the shortlist classifier must remain tool-free")
    if any(call.get("tool_choice") != "auto" for call in model_calls[1:]):
        _fail("tool-capable decisions must preserve automatic tool choice")
    initial_tools = set(model_calls[1].get("tools", ()))
    if not {"web.search", "web.fetch", "tool.request"}.issubset(initial_tools):
        _fail("the current research shortlist is missing")
    if "blockchain.resolve_contract" in initial_tools:
        _fail("the resolver bypassed current tool.request exposure")
    for tool_name, request_call_id in (
        ("blockchain.resolve_contract", "request-resolver"),
        ("blockchain.inspect", "request-inspect-read"),
        ("blockchain.prepare_transaction", "request-prepare"),
        ("blockchain.send_transaction", "request-send"),
    ):
        if not any(
            tool_name in call.get("tools", ())
            and request_call_id in call.get("tool_result_call_ids", ())
            for call in model_calls
        ):
            _fail(f"{tool_name} was not exposed through tool.request")
    for call_id in _SUBSTANTIVE_CALL_IDS:
        if not any(
            call_id in call.get("tool_result_call_ids", ()) for call in model_calls
        ):
            _fail(f"the model did not consume the {call_id} result")

    requested, completed = _tool_events(payload)
    for call_id in _SUBSTANTIVE_CALL_IDS:
        if call_id not in requested or call_id not in completed:
            _fail(f"canonical events are missing for {call_id}")
        request_index, request_event = requested[call_id]
        completed_index, completed_event = completed[call_id]
        if completed_index <= request_index:
            _fail(f"terminal event precedes request for {call_id}")
        if completed_event.get("parent_event_id") != request_event.get("event_id"):
            _fail(f"canonical event correlation is broken for {call_id}")
    for prior, later in (
        ("fetch", "resolve"),
        ("resolve", "inspect-read"),
        ("inspect-read", "prepare"),
        ("prepare", "send"),
        ("send", "operation-status"),
    ):
        if completed[prior][0] >= requested[later][0]:
            _fail(f"causal edge {prior} -> {later} is missing")

    resolution_digest = str(payload.get("resolution_digest", ""))
    preparation_digest = str(payload.get("preparation_digest", ""))
    if not _SHA256_DIGEST.fullmatch(resolution_digest):
        _fail("resolution digest is malformed")
    if not _SHA256_DIGEST.fullmatch(preparation_digest):
        _fail("preparation digest is malformed")
    session_records = payload.get("session_records")
    if not isinstance(session_records, dict) or session_records.get("before") != 0:
        _fail("the scenario did not start from empty session records")
    record_files = set(session_records.get("files", ()))
    if f"{resolution_digest.removeprefix('sha256:')}.json" not in record_files:
        _fail("resolution digest does not join to durable session state")
    if f"{preparation_digest.removeprefix('sha256:')}.json" not in record_files:
        _fail("preparation digest does not join to durable session state")
    if (
        payload.get("resolution", {}).get("data", {}).get("resolution_digest")
        != resolution_digest
    ):
        _fail("resolution result digest does not join")
    read = payload.get("read", {})
    if read.get("data", {}).get("resolution_digest") != resolution_digest:
        _fail("resolved read does not join to resolution")
    if read.get("data", {}).get("result") != ["14"]:
        _fail("resolved read result is wrong")
    preparation = payload.get("preparation", {})
    if preparation.get("resolution_digest") != resolution_digest:
        _fail("preparation does not join to resolution")
    if preparation.get("preparation_digest") != preparation_digest:
        _fail("preparation digest does not join to preparation")
    send = payload.get("send", {})
    if send.get("data", {}).get("preparation_digest") != preparation_digest:
        _fail("submission does not join to preparation")
    for key in ("operation_status", "restart_status"):
        status = payload.get(key, {})
        if status.get("state") != "succeeded":
            _fail(f"{key} is not succeeded")
        data = status.get("data", {})
        if data.get("resolution_digest") != resolution_digest:
            _fail(f"{key} does not join to resolution")
        if data.get("preparation_digest") != preparation_digest:
            _fail(f"{key} does not join to preparation")
        postconditions = data.get("postcondition_results", ())
        if len(postconditions) != 1 or postconditions[0].get("matched") is not True:
            _fail(f"{key} lacks a matched postcondition")
    if not any(
        resolution_digest in call.get("observed_digests", ()) for call in model_calls
    ):
        _fail("the model did not observe the resolution digest")
    if not any(
        preparation_digest in call.get("observed_digests", ()) for call in model_calls
    ):
        _fail("the model did not observe the preparation digest")

    transport = payload.get("transport_calls")
    if not isinstance(transport, list):
        _fail("transport evidence is missing")
    broadcasts = [
        call for call in transport if call.get("rpc_method") == "eth_sendRawTransaction"
    ]
    if len(broadcasts) != 1:
        _fail("the scenario must broadcast exactly once")
    if (
        payload.get("broadcasts_before_restart") != 1
        or payload.get("broadcasts_after_restart") != 1
    ):
        _fail("restart reconstruction resubmitted the transaction")
    owners = payload.get("execution_owners")
    if owners != {
        "command_executor": "RunnerCommandExecutor",
        "tool_adapter": "ToolAdapter",
        "policy_adapter": "PolicyCtlBrainAdapter",
        "send_scope": "POWER_USER",
    }:
        _fail("production command, policy, registry, and tool owners were bypassed")
    approved = payload.get("approved_policy")
    if not isinstance(approved, dict) or approved.get("action") != "allow_once":
        _fail("approved session lacks explicit one-time authorization")
    if not approved.get("grant_id"):
        _fail("approved session lacks a consumed policy grant")
    approved_preview = approved.get("preview", {})
    if approved_preview.get("preparation_digest") != preparation_digest:
        _fail("approved preview does not bind the exact preparation")
    denied = payload.get("denied_policy")
    if not isinstance(denied, dict) or denied.get("session_id") == payload.get(
        "session_id"
    ):
        _fail("denied proof must use a separate policy session")
    denied_approval = denied.get("approval", {})
    if (
        denied_approval.get("action") != "deny"
        or denied_approval.get("grant_id") is not None
    ):
        _fail("denied session lacks an exact denial")
    if not denied_approval.get("preview", {}).get("preparation_digest"):
        _fail("denied session lacks the exact send preview")
    if denied.get("broadcasts_before") != denied.get("broadcasts_after"):
        _fail("denied session attempted a broadcast")
    if denied.get("result_status") != "needs_user":
        _fail("denied policy result was not surfaced")
    audit_events = payload.get("audit_events")
    if not isinstance(audit_events, list) or len(audit_events) != 1:
        _fail("single authorized mutation audit evidence is missing")
    if audit_events[0].get("preparation_digest") != preparation_digest:
        _fail("mutation audit does not join to preparation")
    chain = payload.get("chain", {})
    if chain.get("chain_id") != 31337 or not re.fullmatch(
        r"[0-9a-f]{64}", str(chain.get("contract_code_sha256", ""))
    ):
        _fail("local Anvil fixture truth is missing")
    if payload.get("result", {}).get("status") != "done":
        _fail("the general loop did not complete")


@pytest.fixture(scope="module")
def evidence() -> dict:
    return _run()


def test_local_general_loop_evidence_is_causal_and_restart_safe(evidence) -> None:
    validate_blockchain_autonomous_evidence(evidence)


def test_validator_rejects_broken_digest_join(evidence) -> None:
    mutated = deepcopy(evidence)
    mutated["send"]["data"]["preparation_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="submission does not join"):
        validate_blockchain_autonomous_evidence(mutated)


def test_validator_rejects_denied_broadcast(evidence) -> None:
    mutated = deepcopy(evidence)
    mutated["denied_policy"]["broadcasts_after"] += 1
    with pytest.raises(ValueError, match="denied session attempted a broadcast"):
        validate_blockchain_autonomous_evidence(mutated)


def test_focus_validator_requires_persisted_tool_evidence() -> None:
    payload = {
        "schema_version": "blockchain-autonomous-focus-evidence-v2",
        "scenario_id": "autonomous-public-discovery",
        "protocol": "general_loop_focus_cli",
        "source_commit": "a" * 40,
        "persisted_event_count": 4,
        "requested_tools": [
            "web.search",
            "blockchain.resolve_contract",
            "blockchain.inspect",
        ],
        "successful_resolution_digests": ["sha256:" + "1" * 64],
        "successful_resolved_reads": [
            {
                "resolution_digest": "sha256:" + "1" * 64,
                "block_number": "1",
                "raw_return_digest": "sha256:" + "2" * 64,
            }
        ],
        "response_sha256": "3" * 64,
        "response_bytes": 40,
        "permission_mode": "readonly",
        "allow_unsandboxed_exec": False,
        "approval_prompt_count": 0,
        "broadcast_count": 0,
        "elapsed_seconds": 10.0,
        "max_duration_seconds": 30,
        "terminal_result": "completed",
    }
    focus_runner.validate_evidence(payload)
    payload["requested_tools"] = ["web.search"]
    with pytest.raises(ValueError, match="resolution, and read"):
        focus_runner.validate_evidence(payload)


def test_focus_validator_rejects_unjoined_successful_read() -> None:
    payload = {
        "schema_version": "blockchain-autonomous-focus-evidence-v2",
        "scenario_id": "autonomous-public-discovery",
        "protocol": "general_loop_focus_cli",
        "source_commit": "a" * 40,
        "persisted_event_count": 4,
        "requested_tools": [
            "web.search",
            "blockchain.resolve_contract",
            "blockchain.inspect",
        ],
        "successful_resolution_digests": ["sha256:" + "1" * 64],
        "successful_resolved_reads": [
            {
                "resolution_digest": "sha256:" + "2" * 64,
                "block_number": "1",
                "raw_return_digest": "sha256:" + "3" * 64,
            }
        ],
        "response_sha256": "3" * 64,
        "response_bytes": 40,
        "permission_mode": "readonly",
        "allow_unsandboxed_exec": False,
        "approval_prompt_count": 0,
        "broadcast_count": 0,
        "elapsed_seconds": 10.0,
        "max_duration_seconds": 30,
        "terminal_result": "completed",
    }
    with pytest.raises(ValueError, match="does not join"):
        focus_runner.validate_evidence(payload)


def test_public_read_validator_joins_resolution_and_read() -> None:
    digest = "sha256:" + "1" * 64
    payload = {
        "schema_version": "blockchain-autonomous-public-read-evidence-v2",
        "scenario_id": "approved-public-contract-read",
        "protocol": "direct_runtime_protocol",
        "source_commit": "a" * 40,
        "write_attempts": 0,
        "resolution": {"ok": True, "data": {"resolution_digest": digest}},
        "read": {"ok": True, "data": {"resolution_digest": digest}},
        "broadcast_count": 0,
        "elapsed_seconds": 2.0,
        "max_duration_seconds": 30,
        "terminal_result": "completed",
    }
    public_read_runner.validate_evidence(payload)
    payload["read"]["data"]["resolution_digest"] = "sha256:" + "2" * 64
    with pytest.raises(ValueError, match="does not join"):
        public_read_runner.validate_evidence(payload)


def test_live_validators_reject_stale_approval_inputs() -> None:
    focus = {
        "schema_version": "blockchain-autonomous-focus-evidence-v2",
        "scenario_id": "autonomous-public-discovery",
        "protocol": "general_loop_focus_cli",
        "source_commit": "a" * 40,
        "persisted_event_count": 1,
        "requested_tools": [
            "web.search",
            "blockchain.resolve_contract",
            "blockchain.inspect",
        ],
        "successful_resolution_digests": ["sha256:" + "1" * 64],
        "successful_resolved_reads": [
            {
                "resolution_digest": "sha256:" + "1" * 64,
                "block_number": "1",
                "raw_return_digest": "sha256:" + "2" * 64,
            }
        ],
        "response_sha256": "3" * 64,
        "response_bytes": 40,
        "permission_mode": "readonly",
        "allow_unsandboxed_exec": False,
        "approval_prompt_count": 0,
        "broadcast_count": 0,
        "elapsed_seconds": 1.0,
        "max_duration_seconds": 30,
        "terminal_result": "completed",
    }
    with pytest.raises(ValueError, match="source_commit does not match"):
        focus_runner.validate_evidence(focus, {"source_commit": "b" * 40})


def test_focus_retained_evidence_scan_rejects_secret(tmp_path) -> None:
    sentinel = b"fake-sentinel-provider-key"
    (tmp_path / "evidence.json").write_bytes(b'{"value":"' + sentinel + b'"}')
    with pytest.raises(RuntimeError, match="credential material"):
        focus_runner._assert_retained_evidence_safe(tmp_path, {sentinel})


def test_focus_private_runtime_root_is_removed_after_success(
    tmp_path, monkeypatch
) -> None:
    home_root = tmp_path / "home"
    generated_root = home_root / ".openminion" / "runtime"
    generated_root.mkdir(parents=True)
    monkeypatch.setattr(
        focus_runner,
        "isolate_runtime_roots",
        lambda **_kwargs: generated_root,
    )

    with focus_runner._private_runtime_root() as data_root:
        assert data_root == home_root / ".openminion"
        assert home_root.exists()

    assert not home_root.exists()


def test_focus_private_runtime_root_is_removed_after_failure(
    tmp_path, monkeypatch
) -> None:
    home_root = tmp_path / "home"
    generated_root = home_root / ".openminion" / "runtime"
    generated_root.mkdir(parents=True)
    monkeypatch.setattr(
        focus_runner,
        "isolate_runtime_roots",
        lambda **_kwargs: generated_root,
    )

    with pytest.raises(RuntimeError, match="scenario failed"):
        with focus_runner._private_runtime_root():
            raise RuntimeError("scenario failed")

    assert not home_root.exists()


@pytest.mark.parametrize(
    ("runner", "home_path"),
    (
        (configured_runner, lambda runtime: runtime.parents[1]),
        (debug_runner, lambda runtime: runtime.parent),
        (autonomous_runner, lambda runtime: runtime.parents[1]),
        (public_read_runner, lambda runtime: runtime.parents[1]),
    ),
)
def test_blockchain_runner_runtime_root_is_removed_after_inner_failure(
    monkeypatch, runner, home_path
) -> None:
    sentinels = {
        "OPENMINION_HOME": "/caller/home",
        "OPENMINION_DATA_ROOT": "/caller/data",
        "OPENMINION_GENERATED_ROOT": "/caller/generated",
    }
    for name, value in sentinels.items():
        monkeypatch.setenv(name, value)
    home_root = None

    with pytest.raises(subprocess.TimeoutExpired):
        with runner._private_runtime_root() as runtime_root:
            home_root = home_path(runtime_root)
            assert home_root.exists()
            raise subprocess.TimeoutExpired("anvil", 5)

    assert home_root is not None
    assert not home_root.exists()
    assert {name: os.environ.get(name) for name in sentinels} == sentinels


def test_focus_failure_retains_redacted_evidence_and_cleans_runtime(
    tmp_path, monkeypatch
) -> None:
    sentinel = "fake-sentinel-provider-key"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    home_root = tmp_path / "home"
    generated_root = home_root / ".openminion" / "runtime"
    generated_root.mkdir(parents=True)
    scans: list[tuple[object, object]] = []
    scan = focus_runner._assert_retained_evidence_safe

    def record_scan(root, secrets) -> None:
        scans.append((root, secrets))
        scan(root, secrets)

    def fail_probe(**_kwargs):
        raise RuntimeError(sentinel)

    monkeypatch.setenv(focus_runner.OPT_IN, "1")
    monkeypatch.setattr(
        focus_runner,
        "_required_config",
        lambda: (
            tmp_path / "source.json",
            {"runtime": {"env": {"MINIMAX_API_KEY": sentinel}}},
        ),
    )
    monkeypatch.setattr(focus_runner, "_required", lambda _name: "minimax")
    monkeypatch.setattr(focus_runner, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(focus_runner, "_evidence_root", lambda: evidence_root)
    monkeypatch.setattr(
        focus_runner,
        "isolate_runtime_roots",
        lambda **_kwargs: generated_root,
    )
    monkeypatch.setattr(
        focus_runner,
        "_stage_c_inputs",
        lambda _path, _agent: {"max_duration_seconds": 30},
    )
    monkeypatch.setattr(focus_runner, "FocusProbe", fail_probe)
    monkeypatch.setattr(focus_runner, "_assert_retained_evidence_safe", record_scan)

    with pytest.raises(RuntimeError, match=sentinel):
        focus_runner.main()

    path = evidence_root / "evidence.json"
    retained = json.loads(path.read_text())
    assert retained["terminal_result"] == "failed"
    assert retained["failure"] == {
        "error_type": "RuntimeError",
        "message": "Focus scenario failed; details were not retained.",
    }
    assert "requested_tools" not in retained
    assert sentinel not in path.read_text()
    assert scans == [(evidence_root, {sentinel.encode()})]
    assert not home_root.exists()


def test_focus_failure_evidence_keeps_observed_runtime_facts() -> None:
    evidence = focus_runner._failure_evidence(
        source_commit="a" * 40,
        agent_id="minimax",
        approved={"max_duration_seconds": 30},
        observed={
            "persisted_event_count": 4,
            "persisted_event_types": ["tool.call.requested"],
            "requested_tools": ["shell.exec"],
            "completed_tools": [],
            "permission_mode": "readonly",
            "allow_unsandboxed_exec": False,
            "approval_prompt_count": 0,
            "broadcast_count": 0,
            "elapsed_seconds": 2.0,
        },
        error=ValueError("sensitive detail"),
    )

    assert evidence["terminal_result"] == "failed"
    assert evidence["requested_tools"] == ["shell.exec"]
    assert evidence["persisted_event_count"] == 4
    assert evidence["approval_prompt_count"] == 0
    assert evidence["broadcast_count"] == 0
    assert "sensitive detail" not in json.dumps(evidence)


def _prepare_focus_failure_main(
    tmp_path, monkeypatch, probe_type, read_evidence
) -> object:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    generated_root = tmp_path / "home" / ".openminion" / "runtime"
    generated_root.mkdir(parents=True)
    monkeypatch.setenv(focus_runner.OPT_IN, "1")
    monkeypatch.setattr(
        focus_runner,
        "_required_config",
        lambda: (tmp_path / "source.json", {"runtime": {}}),
    )
    monkeypatch.setattr(focus_runner, "_required", lambda _name: "minimax")
    monkeypatch.setattr(focus_runner, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(focus_runner, "_evidence_root", lambda: evidence_root)
    monkeypatch.setattr(
        focus_runner,
        "isolate_runtime_roots",
        lambda **_kwargs: generated_root,
    )
    monkeypatch.setattr(
        focus_runner,
        "_stage_c_inputs",
        lambda _path, _agent: {"max_duration_seconds": 30},
    )
    monkeypatch.setattr(focus_runner, "FocusProbe", probe_type)
    monkeypatch.setattr(focus_runner, "read_focus_evidence", read_evidence)
    return evidence_root


class _FailingFocusProbe:
    session_id = "abo-focus-minimax"

    def __init__(self, **_kwargs) -> None:
        pass

    def environment(self) -> dict[str, str]:
        return {}

    def session(self, **_kwargs):
        return self

    def __enter__(self):
        return object()

    def __exit__(self, *_args) -> None:
        return None

    def wait_ready(self, _session) -> None:
        pass

    def run_slash(self, _session, _command, **_kwargs) -> None:
        pass

    def run_turn(self, _session, _scenario) -> str:
        raise TimeoutError("provider detail")


def test_focus_timeout_retains_current_runtime_facts(tmp_path, monkeypatch) -> None:
    events = [
        SimpleNamespace(
            session_id="brain-session",
            event_type="tool.call.requested",
            data={
                "canonical_name": "web.search",
                "provider_detail": "must-not-be-retained",
            },
        ),
        SimpleNamespace(
            session_id="brain-session",
            event_type="tool.call.completed",
            data={"canonical_name": "web.search"},
        ),
    ]
    evidence_root = _prepare_focus_failure_main(
        tmp_path,
        monkeypatch,
        _FailingFocusProbe,
        lambda _environment, _session_id: (events, [], "brain-session"),
    )

    with pytest.raises(TimeoutError, match="provider detail"):
        focus_runner.main()

    retained = json.loads((evidence_root / "evidence.json").read_text())
    assert retained["persisted_event_count"] == 2
    assert retained["requested_tools"] == ["web.search"]
    assert retained["completed_tools"] == ["web.search"]
    assert retained["permission_mode"] == "readonly"
    assert retained["allow_unsandboxed_exec"] is False
    assert "approval_prompt_count" not in retained
    assert "broadcast_count" not in retained
    assert "provider detail" not in json.dumps(retained)
    assert "must-not-be-retained" not in json.dumps(retained)


@pytest.mark.parametrize("diagnostic_error", (AssertionError, sqlite3.OperationalError))
def test_focus_timeout_preserves_error_when_runtime_facts_are_unavailable(
    tmp_path, monkeypatch, diagnostic_error
) -> None:
    def fail_read(_environment, _session_id):
        raise diagnostic_error("missing runtime session")

    evidence_root = _prepare_focus_failure_main(
        tmp_path,
        monkeypatch,
        _FailingFocusProbe,
        fail_read,
    )

    with pytest.raises(TimeoutError, match="provider detail"):
        focus_runner.main()

    retained = json.loads((evidence_root / "evidence.json").read_text())
    assert retained["permission_mode"] == "readonly"
    assert retained["allow_unsandboxed_exec"] is False
    assert "persisted_event_count" not in retained
    assert "approval_prompt_count" not in retained
    assert "broadcast_count" not in retained


def test_focus_prepermission_failure_does_not_claim_safety_facts(
    tmp_path, monkeypatch
) -> None:
    class PrepermissionFailureProbe(_FailingFocusProbe):
        def run_slash(self, _session, _command, **_kwargs) -> None:
            raise AssertionError("permission command failed")

    evidence_root = _prepare_focus_failure_main(
        tmp_path,
        monkeypatch,
        PrepermissionFailureProbe,
        lambda _environment, _session_id: pytest.fail(
            "runtime evidence must not be read before permissions are established"
        ),
    )

    with pytest.raises(AssertionError, match="permission command failed"):
        focus_runner.main()

    retained = json.loads((evidence_root / "evidence.json").read_text())
    assert "permission_mode" not in retained
    assert "allow_unsandboxed_exec" not in retained
    assert "approval_prompt_count" not in retained
    assert "broadcast_count" not in retained


def test_focus_source_commit_rejects_dirty_checkout(monkeypatch) -> None:
    monkeypatch.setattr(focus_runner, "_required", lambda _name: "a" * 40)

    def check_output(command, **_kwargs):
        if command[1:3] == ["rev-parse", "HEAD"]:
            return "a" * 40 + "\n"
        return " M tests/e2e/runner.py\n"

    monkeypatch.setattr(focus_runner.subprocess, "check_output", check_output)

    with pytest.raises(RuntimeError, match="clean committed checkout"):
        focus_runner._source_commit()


def test_focus_source_drift_prevents_failure_evidence(tmp_path, monkeypatch) -> None:
    evidence_root = _prepare_focus_failure_main(
        tmp_path,
        monkeypatch,
        _FailingFocusProbe,
        lambda _environment, _session_id: ([], [], "brain-session"),
    )
    calls = 0

    def source_commit() -> str:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("current source commit does not match Stage C approval")
        return "a" * 40

    monkeypatch.setattr(focus_runner, "_source_commit", source_commit)

    with pytest.raises(RuntimeError, match="does not match Stage C approval"):
        focus_runner.main()

    assert calls == 2
    assert not (evidence_root / "evidence.json").exists()


@pytest.mark.parametrize("attribute", ("SIGALRM", "setitimer"))
def test_public_read_deadline_fails_closed_when_unavailable(
    monkeypatch, attribute: str
) -> None:
    monkeypatch.delattr(public_read_runner.signal, attribute)

    with pytest.raises(RuntimeError, match="deadline is unavailable"):
        with public_read_runner._deadline(1):
            pytest.fail("deadline context must not start")


@pytest.mark.parametrize("attribute", ("SIGALRM", "setitimer"))
def test_focus_deadline_fails_closed_when_unavailable(
    monkeypatch, attribute: str
) -> None:
    monkeypatch.delattr(focus_runner.signal, attribute)

    with pytest.raises(RuntimeError, match="deadline is unavailable"):
        with focus_runner._deadline(1):
            pytest.fail("deadline context must not start")


def test_testnet_validator_joins_full_lifecycle() -> None:
    preparation_digest = "sha256:" + "2" * 64
    status = {
        "ok": True,
        "data": {
            "state": "succeeded",
            "preparation_digest": preparation_digest,
            "submission_started": True,
            "broadcast_attempts": 1,
            "postcondition_results": [{"matched": True}],
        },
    }
    payload = {
        "schema_version": "blockchain-autonomous-testnet-write-evidence-v2",
        "protocol": "production_policy_runtime_protocol",
        "source_commit": "a" * 40,
        "config_sha256": "b" * 64,
        "approval_envelope_digest": "sha256:" + "c" * 64,
        "attempt_manifest": {
            "state": "succeeded",
            "preparation_digest": preparation_digest,
            "source_commit": "a" * 40,
            "config_sha256": "b" * 64,
            "approval_envelope_digest": "sha256:" + "c" * 64,
            "attempt_id": "attempt-1",
            "private_root_identifier": "sha256:" + "d" * 64,
            "signer_address": "0x" + "e" * 40,
        },
        "operation_status": deepcopy(status),
        "restart_status": deepcopy(status),
        "audit_events": [{"preparation_digest": preparation_digest}],
        "policy_approval": {
            "action": "allow_once",
            "grant_id": "grant-1",
            "preview": {"preparation_digest": preparation_digest},
        },
        "mutation_invocations_this_entry": 1,
        "mutation_invocations_total": 1,
        "max_broadcasts": 1,
        "key_deletion_attestation": None,
        "private_root_identifier": "sha256:" + "d" * 64,
        "retained_secret_scan": {
            "schema_version": "blockchain-testnet-secret-scan-v1",
            "attempt_id": "attempt-1",
            "private_root_identifier": "sha256:" + "d" * 64,
            "signer_address": "0x" + "e" * 40,
            "operator_id": "test-operator",
            "secret_absent": True,
            "source": "runner_initial",
            "scanned_at": "2026-10-16T00:00:00+00:00",
        },
        "execution_owners": {
            "command_executor": "RunnerCommandExecutor",
            "tool_adapter": "ToolAdapter",
            "policy_adapter": "PolicyCtlBrainAdapter",
            "send_scope": "POWER_USER",
        },
    }
    testnet_runner.validate_evidence(payload)
    payload["policy_approval"]["preview"]["preparation_digest"] = "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="one-time policy approval"):
        testnet_runner.validate_evidence(payload)
    payload["policy_approval"]["preview"]["preparation_digest"] = preparation_digest
    payload["restart_status"]["data"]["state"] = "pending"
    with pytest.raises(ValueError, match="restart_status is not succeeded"):
        testnet_runner.validate_evidence(payload)


def _approved_testnet_attempt(tmp_path) -> dict:
    return {
        "attempt_id": "attempt-1",
        "source_commit": "a" * 40,
        "config_sha256": "b" * 64,
        "approval_envelope_digest": "sha256:" + "c" * 64,
        "expected_chain_id": 11155111,
        "expected_genesis_hash": "0x" + "1" * 64,
        "expected_checkpoint": None,
        "expected_rpc_origin": "https://rpc.example",
        "signer_address": "0x" + "2" * 40,
        "contract_address": "0x" + "3" * 40,
        "canonical_call_digest": "sha256:" + "4" * 64,
        "max_total_fee_wei": "1000",
        "confirmation_depth": 1,
        "max_duration_seconds": 30,
        "precondition_digest": "sha256:" + "5" * 64,
        "postcondition_digest": "sha256:" + "6" * 64,
        "private_root_identifier": "sha256:" + "a" * 64,
        "operator_id": "test-operator",
        "attempt_root": tmp_path / "attempt",
        "config_path": tmp_path / "config.json",
    }


def _testnet_resolution(approved: dict) -> dict:
    return {
        "ok": True,
        "data": {
            "resolution_digest": "sha256:" + "7" * 64,
            "expected_chain_id": approved["expected_chain_id"],
            "observed_chain_id": approved["expected_chain_id"],
            "expected_genesis_hash": approved["expected_genesis_hash"],
            "observed_genesis_hash": approved["expected_genesis_hash"],
            "expected_checkpoint": approved["expected_checkpoint"],
            "observed_checkpoint": approved["expected_checkpoint"],
            "rpc_origin": approved["expected_rpc_origin"],
            "contract_address": approved["contract_address"],
        },
    }


def _testnet_terminal_status(preparation_digest: str) -> dict:
    return {
        "ok": True,
        "data": {
            "state": "succeeded",
            "preparation_digest": preparation_digest,
            "submission_started": True,
            "broadcast_attempts": 1,
            "postcondition_results": [{"matched": True}],
        },
    }


def test_testnet_approval_envelope_binds_local_inputs(tmp_path, monkeypatch) -> None:
    signer = "0x" + "2" * 40
    contract = "0x" + "3" * 40
    precondition = {
        "function_signature": "balanceOf(address)",
        "arguments": [signer],
        "expected_result": ["0"],
    }
    postcondition = {
        "function_signature": "balanceOf(address)",
        "arguments": [signer],
        "expected_result": ["1"],
    }
    payload = {
        "network_class": "disposable_testnet",
        "signer_address": signer,
        "signer_secret_env": "TEST_SIGNER_SECRET",
        "max_total_fee_wei": "1000",
        "confirmation_depth": 1,
        "resolve_request": {
            "rpc_url": "https://rpc.example",
            "expected_chain_id": 11155111,
            "expected_genesis_hash": "0x" + "1" * 64,
            "contract_address": contract,
        },
        "precondition": precondition,
        "prepare_request": {
            "function_signature": "deposit()",
            "arguments": [],
            "value_wei": "1",
            "postconditions": [postcondition],
        },
    }
    config_path = tmp_path / "testnet-write.json"
    config_path.write_text(json.dumps(payload, sort_keys=True))
    attempt_root = tmp_path / "attempt"
    monkeypatch.setattr(testnet_runner, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(testnet_runner, "_source_status", lambda: "")
    approved = {
        "SOURCE_COMMIT": "a" * 40,
        "CONFIG_SHA256": testnet_runner._file_sha256(config_path),
        "PARENT_ROOT": str(tmp_path),
        "ATTEMPT_ROOT": str(attempt_root),
        "CHAIN_ID": "11155111",
        "GENESIS_HASH": "0x" + "1" * 64,
        "RPC_ORIGIN": "https://rpc.example",
        "SIGNER_ADDRESS": signer,
        "CONTRACT_ADDRESS": contract,
        "FUNCTION_SIGNATURE": "deposit()",
        "ARGUMENTS_DIGEST": testnet_runner._canonical_digest([]),
        "VALUE_WEI": "1",
        "MAX_TOTAL_FEE_WEI": "1000",
        "CONFIRMATION_DEPTH": "1",
        "MAX_DURATION_SECONDS": "30",
        "PRECONDITION_DIGEST": testnet_runner._canonical_digest(precondition),
        "POSTCONDITION_DIGEST": testnet_runner._canonical_digest(postcondition),
        "ATTEMPT_ID": "attempt-1",
        "OPERATOR_ID": "test-operator",
        "CHECKPOINT_DIGEST": testnet_runner._canonical_digest(None),
        "MUTATION_INVOCATIONS": "1",
        "MAX_BROADCASTS": "1",
    }
    for suffix, value in approved.items():
        monkeypatch.setenv(f"{testnet_runner.APPROVAL_PREFIX}{suffix}", value)

    result = testnet_runner._approved_attempt(
        config_path,
        payload,
        testnet_runner._file_sha256(config_path),
    )

    assert result["attempt_root"] == attempt_root
    assert result["canonical_call_digest"] == testnet_runner._canonical_digest(
        {"function_signature": "deposit()", "arguments": [], "value_wei": "1"}
    )
    first_digest = result["approval_envelope_digest"]
    monkeypatch.setenv(
        f"{testnet_runner.APPROVAL_PREFIX}ATTEMPT_ROOT",
        str(tmp_path / "second-attempt"),
    )
    second = testnet_runner._approved_attempt(
        config_path,
        payload,
        testnet_runner._file_sha256(config_path),
    )
    assert second["approval_envelope_digest"] != first_digest


def test_testnet_checkout_paths_are_rejected_before_runtime(
    tmp_path, monkeypatch
) -> None:
    config_path = tmp_path / "testnet-write.json"
    config_path.write_text("{}")
    monkeypatch.setattr(testnet_runner, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(testnet_runner, "_source_status", lambda: "")
    monkeypatch.setenv(f"{testnet_runner.APPROVAL_PREFIX}SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv(
        f"{testnet_runner.APPROVAL_PREFIX}CONFIG_SHA256",
        testnet_runner._file_sha256(config_path),
    )
    monkeypatch.setenv(
        f"{testnet_runner.APPROVAL_PREFIX}PARENT_ROOT", str(testnet_runner.ROOT)
    )
    monkeypatch.setenv(
        f"{testnet_runner.APPROVAL_PREFIX}ATTEMPT_ROOT",
        str(testnet_runner.ROOT / ".testnet-write-attempt"),
    )

    with pytest.raises(RuntimeError, match="attempt root must be outside"):
        testnet_runner._approved_attempt(
            config_path,
            {},
            testnet_runner._file_sha256(config_path),
        )

    external_attempt = tmp_path / "attempt"
    monkeypatch.setenv(f"{testnet_runner.APPROVAL_PREFIX}PARENT_ROOT", str(tmp_path))
    monkeypatch.setenv(
        f"{testnet_runner.APPROVAL_PREFIX}ATTEMPT_ROOT", str(external_attempt)
    )
    with pytest.raises(RuntimeError, match="config must be outside"):
        testnet_runner._approved_attempt(
            testnet_runner.ROOT
            / "tests/e2e/fixtures/blockchain/testnet_write.example.json",
            {},
            testnet_runner._file_sha256(config_path),
        )


def test_testnet_dirty_source_is_rejected_before_runtime(monkeypatch) -> None:
    monkeypatch.setattr(testnet_runner, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(testnet_runner, "_source_status", lambda: " M runner.py")

    with pytest.raises(RuntimeError, match="clean committed checkout"):
        testnet_runner._assert_clean_source("a" * 40)


def test_testnet_config_drift_is_rejected_before_evidence(
    tmp_path, monkeypatch
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text('{"version":1}')
    approved = _approved_testnet_attempt(tmp_path)
    approved["config_path"] = config_path
    approved["config_sha256"] = testnet_runner._file_sha256(config_path)
    monkeypatch.setattr(testnet_runner, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(testnet_runner, "_source_status", lambda: "")
    config_path.write_text('{"version":2}')

    with pytest.raises(RuntimeError, match="config changed"):
        testnet_runner._assert_approval_unchanged(approved)


def test_testnet_recovery_requires_secret_scan_attestation(
    tmp_path, monkeypatch
) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()
    monkeypatch.delenv(testnet_runner.SCAN_ATTESTATION_ENV, raising=False)

    with pytest.raises(RuntimeError, match="requires a caller-owned"):
        testnet_runner._required_recovery_scan(approved)


def test_testnet_recovery_accepts_joined_external_scan(tmp_path, monkeypatch) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()
    attestation = {
        "schema_version": "blockchain-testnet-secret-scan-v1",
        "attempt_id": approved["attempt_id"],
        "private_root_identifier": approved["private_root_identifier"],
        "signer_address": approved["signer_address"],
        "operator_id": approved["operator_id"],
        "secret_absent": True,
        "source": "caller_recovery",
        "scanned_at": "2026-10-16T00:00:00+00:00",
    }
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(attestation))
    monkeypatch.setenv(testnet_runner.SCAN_ATTESTATION_ENV, str(path))

    assert testnet_runner._required_recovery_scan(approved) == attestation
    assert (
        json.loads(
            (
                approved["attempt_root"] / testnet_runner.SCAN_ATTESTATION_NAME
            ).read_text()
        )
        == attestation
    )


def test_testnet_example_uses_non_approval_mutation(monkeypatch) -> None:
    path = (
        testnet_runner.ROOT / "tests/e2e/fixtures/blockchain/testnet_write.example.json"
    )
    monkeypatch.setenv(testnet_runner.CONFIG_ENV, str(path))
    resolved, payload, config_sha256 = testnet_runner._required_config()

    assert resolved == path
    assert config_sha256 == testnet_runner._file_sha256(path)
    assert payload["prepare_request"]["function_signature"] == "deposit()"
    assert payload["prepare_request"]["arguments"] == []
    assert payload["prepare_request"]["value_wei"] == "1"
    assert payload["precondition"]["function_signature"] == "balanceOf(address)"
    assert (
        payload["prepare_request"]["postconditions"][0]["function_signature"]
        == "balanceOf(address)"
    )


def test_testnet_attempt_without_manifest_is_abandoned(tmp_path) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()

    with pytest.raises(RuntimeError, match="no complete manifest"):
        testnet_runner._resume_manifest(approved)


def test_testnet_prepared_attempt_without_operation_closes_not_submitted(
    tmp_path, monkeypatch
) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()
    preparation_digest = "sha256:" + "8" * 64
    testnet_runner._write_manifest(
        approved,
        state="prepared",
        preparation_digest=preparation_digest,
    )
    monkeypatch.setattr(testnet_runner, "_load_operation", lambda *_args: None)

    with pytest.raises(RuntimeError, match="did not create an operation record"):
        testnet_runner._resume_manifest(approved)

    manifest = json.loads(
        (approved["attempt_root"] / testnet_runner.MANIFEST_NAME).read_text()
    )
    assert manifest["state"] == "not_submitted"


@pytest.mark.parametrize("state", ("broadcast_unknown", "pending", "succeeded"))
def test_testnet_claimed_attempt_enters_status_only_recovery(
    tmp_path, monkeypatch, state: str
) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()
    preparation_digest = "sha256:" + "8" * 64
    testnet_runner._write_manifest(
        approved,
        state="prepared",
        preparation_digest=preparation_digest,
    )
    monkeypatch.setattr(
        testnet_runner,
        "_load_operation",
        lambda *_args: {"submission_started": True, "state": state},
    )

    manifest = testnet_runner._resume_manifest(approved)

    assert manifest["state"] == state
    assert manifest["preparation_digest"] == preparation_digest


def test_testnet_observed_chain_mismatch_stops_before_prepare(tmp_path) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    resolution = _testnet_resolution(approved)
    resolution["data"]["observed_chain_id"] = 1

    class Execution:
        calls: list[str] = []

        def execute_raw(self, *, name, **_kwargs):
            self.calls.append(name)
            return {"outputs": resolution}

    execution = Execution()
    with pytest.raises(RuntimeError, match="observed observed_chain_id"):
        testnet_runner._resolve_and_prepare(
            execution,
            {"resolve_request": {}},
            approved,
        )

    assert execution.calls == ["blockchain.resolve_contract"]


def test_testnet_precondition_mismatch_stops_before_prepare(tmp_path) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    payload = {
        "resolve_request": {},
        "precondition": {
            "function_signature": "balanceOf(address)",
            "arguments": [approved["signer_address"]],
            "expected_result": ["1"],
        },
        "prepare_request": {},
    }
    outputs = [
        _testnet_resolution(approved),
        {"ok": True, "data": {"result": ["0"]}},
    ]

    class Execution:
        calls: list[str] = []

        def execute_raw(self, *, name, **_kwargs):
            self.calls.append(name)
            return {"outputs": outputs.pop(0)}

    execution = Execution()
    with pytest.raises(RuntimeError, match="precondition does not match"):
        testnet_runner._resolve_and_prepare(execution, payload, approved)

    assert execution.calls == ["blockchain.resolve_contract", "blockchain.inspect"]


def test_testnet_response_loss_recovers_from_claim_without_resend(
    tmp_path, monkeypatch
) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()
    preparation_digest = "sha256:" + "8" * 64
    preparation = {"ok": True, "preparation_digest": preparation_digest}
    status = _testnet_terminal_status(preparation_digest)

    class Execution:
        approval = {"action": "allow_once"}

        def close(self):
            return None

    monkeypatch.setattr(testnet_runner, "_metadata", lambda _payload: {})
    monkeypatch.setattr(testnet_runner, "_execution", lambda *_args: Execution())
    monkeypatch.setattr(
        testnet_runner,
        "_resolve_and_prepare",
        lambda *_args: ({"ok": True}, {"ok": True}, preparation),
    )
    monkeypatch.setattr(
        testnet_runner,
        "_send_once",
        lambda *_args: (_ for _ in ()).throw(ConnectionError("response lost")),
    )
    monkeypatch.setattr(
        testnet_runner,
        "_load_operation",
        lambda *_args: {"submission_started": True, "state": "broadcast_unknown"},
    )
    monkeypatch.setattr(
        testnet_runner, "_terminal_status", lambda *_args, **_kwargs: status
    )
    monkeypatch.setattr(
        testnet_runner, "_inspect_status", lambda *_args, **_kwargs: status
    )
    monkeypatch.setattr(testnet_runner, "_read_audit_events", lambda *_args: [])

    evidence = testnet_runner._run_initial({}, approved, "sentinel-secret")

    assert evidence["send"] is None
    assert evidence["mutation_invocations_this_entry"] == 1
    assert evidence["operation_status"] == status


def test_testnet_recovery_never_loads_signer_or_sends(tmp_path, monkeypatch) -> None:
    approved = _approved_testnet_attempt(tmp_path)
    approved["attempt_root"].mkdir()
    preparation_digest = "sha256:" + "8" * 64
    manifest = testnet_runner._write_manifest(
        approved,
        state="broadcast_unknown",
        preparation_digest=preparation_digest,
    )
    status = _testnet_terminal_status(preparation_digest)
    monkeypatch.setattr(
        testnet_runner, "_terminal_status", lambda *_args, **_kwargs: status
    )
    monkeypatch.setattr(
        testnet_runner, "_inspect_status", lambda *_args, **_kwargs: status
    )
    monkeypatch.setattr(testnet_runner, "_read_audit_events", lambda *_args: [])
    monkeypatch.setattr(
        testnet_runner,
        "_load_signer_secret",
        lambda *_args: pytest.fail("recovery loaded the signer"),
    )
    monkeypatch.setattr(
        testnet_runner,
        "_send_once",
        lambda *_args: pytest.fail("recovery attempted another send"),
    )

    evidence = testnet_runner._run_recovery(approved, manifest)

    assert evidence["mutation_invocations_this_entry"] == 0
    assert evidence["attempt_manifest"]["state"] == "succeeded"


def test_testnet_local_approval_mismatch_precedes_runtime(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv(testnet_runner.OPT_IN, "1")
    monkeypatch.setattr(
        testnet_runner,
        "_required_config",
        lambda: (tmp_path, {}, "a" * 64),
    )
    monkeypatch.setattr(
        testnet_runner,
        "_approved_attempt",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("approval mismatch")),
    )
    monkeypatch.setattr(
        testnet_runner,
        "_load_signer_secret",
        lambda *_args: pytest.fail("approval mismatch loaded the signer"),
    )

    with pytest.raises(RuntimeError, match="approval mismatch"):
        testnet_runner.main()


@pytest.mark.parametrize(
    ("runner", "opt_in", "config_env"),
    (
        (focus_runner, focus_runner.OPT_IN, focus_runner.CONFIG_ENV),
        (public_read_runner, public_read_runner.OPT_IN, public_read_runner.CONFIG_ENV),
        (testnet_runner, testnet_runner.OPT_IN, testnet_runner.CONFIG_ENV),
    ),
)
def test_opt_in_runners_fail_clearly_without_required_config(
    monkeypatch, runner, opt_in: str, config_env: str
) -> None:
    monkeypatch.setenv(opt_in, "1")
    monkeypatch.delenv(config_env, raising=False)
    with pytest.raises(
        RuntimeError, match=rf"^{config_env} is required when {opt_in}=1$"
    ):
        runner._required_config()


def test_focus_runner_builds_private_readonly_blockchain_config(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps(
            {
                "runtime": {"env": {"MINIMAX_API_KEY": "sentinel-provider-key"}},
                "agents": {"minimax": {"provider": "openai"}},
            }
        )
    )
    monkeypatch.setenv(focus_runner.OPT_IN, "1")
    monkeypatch.setenv(focus_runner.CONFIG_ENV, str(source))

    resolved, payload = focus_runner._required_config()
    private = focus_runner._write_private_config(payload, tmp_path / "runtime")
    private_payload = json.loads(private.read_text())

    assert resolved == source
    assert private.stat().st_mode & 0o777 == 0o600
    assert private_payload["runtime"]["tools"]["blockchain"] == {"enabled": True}
    assert private_payload["runtime"]["env"]["MINIMAX_API_KEY"] == (
        "sentinel-provider-key"
    )
