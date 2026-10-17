from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tests.helpers.runtime_roots import (  # noqa: E402
    RUNTIME_ROOT_ENV_VARS,
    configure_runtime_roots,
    isolate_runtime_roots,
)

IMPORT_RUNTIME_ROOT = isolate_runtime_roots(prefix="openminion-abo-testnet-import-")

from tests.e2e.runners.run_blockchain_autonomous_local import (  # noqa: E402
    ProductionBlockchainExecution,
    build_blockchain_policy,
)

OPT_IN = "OPENMINION_BLOCKCHAIN_TESTNET_WRITE_E2E"
CONFIG_ENV = "OPENMINION_BLOCKCHAIN_TESTNET_WRITE_CONFIG"
APPROVAL_PREFIX = "OPENMINION_BLOCKCHAIN_TESTNET_WRITE_APPROVED_"
MANIFEST_NAME = "attempt.json"
EVIDENCE_NAME = "evidence.json"
SCAN_ATTESTATION_NAME = "secret-scan.json"
SCAN_ATTESTATION_ENV = "OPENMINION_BLOCKCHAIN_TESTNET_WRITE_SCAN_ATTESTATION"
SESSION_ID = "abo-disposable-testnet-write"
TERMINAL_STATES = {
    "succeeded",
    "reverted",
    "postcondition_failed",
    "reorged",
}

from openminion.base.config.env import EnvironmentConfig  # noqa: E402
from openminion.base.config.runtime.tools import (  # noqa: E402
    BlockchainToolRuntimeConfig,
    ToolRuntimeConfig,
)
from openminion.modules.brain.adapters.tool.runtime import ToolAdapter  # noqa: E402
from openminion.modules.brain.schemas import BudgetCounters, WorkingState  # noqa: E402
from openminion.modules.brain.schemas.commands import ToolCommand  # noqa: E402
from openminion.modules.policy.models import PolicyConfig, RiskSpec  # noqa: E402
from openminion.modules.policy.runtime.service import PolicyCtl  # noqa: E402
from openminion.modules.tool.registry import ToolRegistry  # noqa: E402
from openminion.tools.blockchain import plugin as blockchain_plugin  # noqa: E402
from openminion.tools.blockchain import runtime as blockchain_runtime  # noqa: E402
from openminion.tools.blockchain.preparations import (  # noqa: E402
    SessionRecordError,
    load_operation_record,
)
from openminion.tools.blockchain.public_https import request_public_https  # noqa: E402
from openminion.tools.blockchain.resolved_schemas import ResolveContractArgs  # noqa: E402
from openminion.tools.blockchain.transaction_schemas import (  # noqa: E402
    EqualityPostcondition,
    ResolvedContractCallArgs,
    operation_digest,
    validate_operation_record,
)


def _required(name: str) -> str:
    value = str(os.getenv(name, "") or "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_commit() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def _source_status() -> str:
    return subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
    ).strip()


def _assert_clean_source(expected_commit: str) -> str:
    source_commit = _source_commit()
    if source_commit != expected_commit:
        raise RuntimeError("current source commit does not match write approval")
    if _source_status():
        raise RuntimeError("testnet write requires a clean committed checkout")
    return source_commit


def _required_config() -> tuple[Path, dict[str, Any], str]:
    raw = str(os.getenv(CONFIG_ENV, "") or "").strip()
    if not raw:
        raise RuntimeError(f"{CONFIG_ENV} is required when {OPT_IN}=1")
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"{CONFIG_ENV} does not name a readable file: {path}")
    config_bytes = path.read_bytes()
    config_sha256 = hashlib.sha256(config_bytes).hexdigest()
    payload = json.loads(config_bytes)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{CONFIG_ENV} must contain an object")
    if payload.get("network_class") != "disposable_testnet":
        raise RuntimeError(f"{CONFIG_ENV} network_class must be disposable_testnet")
    for field in ("resolve_request", "prepare_request", "precondition"):
        if not isinstance(payload.get(field), dict):
            raise RuntimeError(f"{CONFIG_ENV} must contain a {field} object")
    for field in ("signer_address", "signer_secret_env"):
        if not str(payload.get(field, "") or "").strip():
            raise RuntimeError(f"{CONFIG_ENV} must contain {field}")
    postconditions = payload["prepare_request"].get("postconditions")
    if not isinstance(postconditions, list) or len(postconditions) != 1:
        raise RuntimeError(f"{CONFIG_ENV} must contain one exact postcondition")
    resolve_request = ResolveContractArgs.model_validate(
        payload["resolve_request"]
    ).model_dump(mode="json")
    precondition = EqualityPostcondition.model_validate(
        payload["precondition"]
    ).model_dump(mode="json")
    prepare_request = ResolvedContractCallArgs.model_validate(
        {
            **payload["prepare_request"],
            "kind": "resolved_contract_call",
            "resolution_digest": "sha256:" + "0" * 64,
        }
    ).model_dump(mode="json")
    prepare_request.pop("kind")
    prepare_request.pop("resolution_digest")
    if prepare_request["function_signature"] == "approve(address,uint256)":
        raise RuntimeError("token approval is outside the testnet acceptance lane")
    return (
        path,
        {
            **payload,
            "resolve_request": resolve_request,
            "precondition": precondition,
            "prepare_request": prepare_request,
        },
        config_sha256,
    )


def _approved_attempt(
    config_path: Path,
    payload: dict[str, Any],
    config_sha256: str,
) -> dict[str, Any]:
    approved_source_commit = _required(f"{APPROVAL_PREFIX}SOURCE_COMMIT")
    source_commit = _assert_clean_source(approved_source_commit)
    if config_sha256 != _required(f"{APPROVAL_PREFIX}CONFIG_SHA256"):
        raise RuntimeError("testnet config fingerprint does not match write approval")

    approved_parent = (
        Path(_required(f"{APPROVAL_PREFIX}PARENT_ROOT")).expanduser().resolve()
    )
    attempt_root = (
        Path(_required(f"{APPROVAL_PREFIX}ATTEMPT_ROOT")).expanduser().resolve()
    )
    for label, path in (("config", config_path), ("attempt root", attempt_root)):
        try:
            path.relative_to(ROOT)
        except ValueError:
            continue
        raise RuntimeError(f"testnet {label} must be outside the OpenMinion checkout")
    if not approved_parent.is_dir():
        raise RuntimeError("approved parent root does not exist")
    try:
        attempt_root.relative_to(approved_parent)
    except ValueError as exc:
        raise RuntimeError("attempt root is outside the approved parent root") from exc

    resolve_request = payload["resolve_request"]
    prepare_request = payload["prepare_request"]
    precondition = payload["precondition"]
    postcondition = prepare_request["postconditions"][0]
    parsed_rpc = urlsplit(str(resolve_request.get("rpc_url", "")))
    rpc_origin = f"{parsed_rpc.scheme}://{parsed_rpc.netloc}"
    if parsed_rpc.username or parsed_rpc.password:
        raise RuntimeError("testnet RPC URL must not contain credentials")

    expected = {
        "expected_chain_id": int(_required(f"{APPROVAL_PREFIX}CHAIN_ID")),
        "expected_genesis_hash": _required(f"{APPROVAL_PREFIX}GENESIS_HASH").lower(),
        "expected_rpc_origin": _required(f"{APPROVAL_PREFIX}RPC_ORIGIN"),
        "signer_address": _required(f"{APPROVAL_PREFIX}SIGNER_ADDRESS").lower(),
        "contract_address": _required(f"{APPROVAL_PREFIX}CONTRACT_ADDRESS").lower(),
        "function_signature": _required(f"{APPROVAL_PREFIX}FUNCTION_SIGNATURE"),
        "arguments_digest": _required(f"{APPROVAL_PREFIX}ARGUMENTS_DIGEST"),
        "value_wei": _required(f"{APPROVAL_PREFIX}VALUE_WEI"),
        "max_total_fee_wei": _required(f"{APPROVAL_PREFIX}MAX_TOTAL_FEE_WEI"),
        "confirmation_depth": int(_required(f"{APPROVAL_PREFIX}CONFIRMATION_DEPTH")),
        "max_duration_seconds": int(
            _required(f"{APPROVAL_PREFIX}MAX_DURATION_SECONDS")
        ),
        "precondition_digest": _required(f"{APPROVAL_PREFIX}PRECONDITION_DIGEST"),
        "postcondition_digest": _required(f"{APPROVAL_PREFIX}POSTCONDITION_DIGEST"),
        "attempt_id": _required(f"{APPROVAL_PREFIX}ATTEMPT_ID"),
        "operator_id": _required(f"{APPROVAL_PREFIX}OPERATOR_ID"),
    }
    checkpoint = resolve_request.get("expected_checkpoint")
    if _canonical_digest(checkpoint) != _required(
        f"{APPROVAL_PREFIX}CHECKPOINT_DIGEST"
    ):
        raise RuntimeError("testnet checkpoint does not match write approval")
    if not 1 <= expected["max_duration_seconds"] <= 900:
        raise RuntimeError(
            "approved maximum duration must be between 1 and 900 seconds"
        )
    if not 1 <= expected["confirmation_depth"] <= 64:
        raise RuntimeError("approved confirmation depth must be between 1 and 64")
    if _required(f"{APPROVAL_PREFIX}MUTATION_INVOCATIONS") != "1":
        raise RuntimeError("write approval must allow exactly one mutation invocation")
    if _required(f"{APPROVAL_PREFIX}MAX_BROADCASTS") != "1":
        raise RuntimeError("write approval must allow at most one broadcast")

    actual = {
        "expected_chain_id": int(resolve_request.get("expected_chain_id", 0)),
        "expected_genesis_hash": str(
            resolve_request.get("expected_genesis_hash", "")
        ).lower(),
        "expected_rpc_origin": rpc_origin,
        "signer_address": str(payload.get("signer_address", "")).lower(),
        "contract_address": str(resolve_request.get("contract_address", "")).lower(),
        "function_signature": str(prepare_request.get("function_signature", "")),
        "arguments_digest": _canonical_digest(prepare_request.get("arguments")),
        "value_wei": str(prepare_request.get("value_wei", "")),
        "max_total_fee_wei": str(payload.get("max_total_fee_wei", "")),
        "confirmation_depth": int(payload.get("confirmation_depth", 0)),
        "precondition_digest": _canonical_digest(precondition),
        "postcondition_digest": _canonical_digest(postcondition),
    }
    for key, value in actual.items():
        if value != expected[key]:
            raise RuntimeError(f"testnet {key} does not match write approval")

    call_digest = _canonical_digest(
        {
            "function_signature": prepare_request["function_signature"],
            "arguments": prepare_request.get("arguments", []),
            "value_wei": str(prepare_request["value_wei"]),
        }
    )
    private_root_identifier = _canonical_digest(str(attempt_root))
    envelope = {
        "source_commit": source_commit,
        "config_sha256": config_sha256,
        **expected,
        "expected_checkpoint": checkpoint,
        "canonical_call_digest": call_digest,
        "precondition": precondition,
        "postcondition": postcondition,
        "private_root_identifier": private_root_identifier,
        "mutation_invocations": 1,
        "max_broadcasts": 1,
    }
    return {
        **envelope,
        "approval_envelope_digest": _canonical_digest(envelope),
        "attempt_root": attempt_root,
        "config_path": config_path,
    }


def _manifest_bindings(approved: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "blockchain-testnet-attempt-v1",
        "attempt_id": approved["attempt_id"],
        "source_commit": approved["source_commit"],
        "config_sha256": approved["config_sha256"],
        "approval_envelope_digest": approved["approval_envelope_digest"],
        "expected_chain_id": approved["expected_chain_id"],
        "expected_genesis_hash": approved["expected_genesis_hash"],
        "expected_checkpoint": approved["expected_checkpoint"],
        "rpc_origin": approved["expected_rpc_origin"],
        "signer_address": approved["signer_address"],
        "contract_address": approved["contract_address"],
        "canonical_call_digest": approved["canonical_call_digest"],
        "max_total_fee_wei": approved["max_total_fee_wei"],
        "confirmation_depth": approved["confirmation_depth"],
        "max_duration_seconds": approved["max_duration_seconds"],
        "precondition_digest": approved["precondition_digest"],
        "postcondition_digest": approved["postcondition_digest"],
        "private_root_identifier": approved["private_root_identifier"],
    }


def _assert_approval_unchanged(approved: Mapping[str, Any]) -> None:
    _assert_clean_source(str(approved["source_commit"]))
    if _file_sha256(Path(approved["config_path"])) != approved["config_sha256"]:
        raise RuntimeError("testnet config changed after approval validation")


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    descriptor, raw_temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(raw_temporary)
    os.fchmod(descriptor, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_manifest(
    approved: Mapping[str, Any], *, state: str, preparation_digest: str
) -> dict[str, Any]:
    manifest = {
        **_manifest_bindings(approved),
        "state": state,
        "preparation_digest": preparation_digest,
    }
    _write_json_atomic(Path(approved["attempt_root"]) / MANIFEST_NAME, manifest)
    return manifest


def _read_manifest(approved: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(approved["attempt_root"]) / MANIFEST_NAME
    if not path.is_file():
        raise RuntimeError(
            "attempt root has no complete manifest; use a separately approved fresh root"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("attempt manifest is invalid")
    expected_keys = {*_manifest_bindings(approved), "state", "preparation_digest"}
    if set(payload) != expected_keys:
        raise RuntimeError("attempt manifest fields are invalid")
    for key, value in _manifest_bindings(approved).items():
        if payload.get(key) != value:
            raise RuntimeError(f"attempt manifest {key} does not match approval")
    digest = str(payload.get("preparation_digest", ""))
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise RuntimeError("attempt manifest preparation digest is invalid")
    return payload


def _runtime_env(attempt_root: Path) -> EnvironmentConfig:
    values: dict[str, str] = {}
    configure_runtime_roots(attempt_root, values)
    return EnvironmentConfig(values=values)


@contextmanager
def _configured_runtime(attempt_root: Path) -> Iterator[EnvironmentConfig]:
    previous = {name: os.environ.get(name) for name in RUNTIME_ROOT_ENV_VARS}
    configure_runtime_roots(attempt_root)
    try:
        yield _runtime_env(attempt_root)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _load_operation(
    preparation_digest: str, env: EnvironmentConfig
) -> dict[str, Any] | None:
    try:
        return load_operation_record(
            preparation_digest,
            session_id=SESSION_ID,
            env=env,
            validator=validate_operation_record,
            digester=operation_digest,
        )
    except SessionRecordError as exc:
        if exc.reason == "unavailable":
            return None
        raise RuntimeError("stored operation record is invalid") from exc


def _resume_manifest(approved: Mapping[str, Any]) -> dict[str, Any]:
    manifest = _read_manifest(approved)
    env = _runtime_env(Path(approved["attempt_root"]))
    operation = _load_operation(manifest["preparation_digest"], env)
    if operation is None:
        _write_manifest(
            approved,
            state="not_submitted",
            preparation_digest=manifest["preparation_digest"],
        )
        raise RuntimeError(
            "attempt did not create an operation record; use a separately approved fresh root"
        )
    if operation.get("submission_started") is not True:
        raise RuntimeError("stored operation did not start submission")
    return _write_manifest(
        approved,
        state=str(operation["state"]),
        preparation_digest=manifest["preparation_digest"],
    )


def _metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "runtime_tools": {
            "blockchain": {
                "enabled": True,
                "writes_enabled": True,
                "signer_secret_key": "abo-testnet-signer",
                "signer_secret_namespace": "blockchain",
                "max_total_fee_wei": str(payload["max_total_fee_wei"]),
                "confirmation_depth": int(payload["confirmation_depth"]),
            }
        }
    }


def _status_metadata(approved: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "runtime_tools": {
            "blockchain": {
                "enabled": True,
                "confirmation_depth": int(approved["confirmation_depth"]),
            }
        }
    }


def _execution(
    data_root: Path,
    metadata: dict[str, Any],
    signer_secret: str,
) -> ProductionBlockchainExecution:
    registry = ToolRegistry()
    blockchain_plugin.register(registry)
    policy_ctl = PolicyCtl.with_sqlite(
        data_root / "policy.sqlite",
        config=PolicyConfig(mode="enforce"),
    )
    policy_ctl.register_risk(
        "blockchain.send_transaction",
        RiskSpec(
            risk_class="financial",
            side_effects="external_account",
            reversibility="irreversible",
            default_confirm=True,
        ),
    )
    blockchain = metadata["runtime_tools"]["blockchain"]
    adapter = ToolAdapter(
        workspace_root=data_root,
        runtime_config=SimpleNamespace(
            tools=ToolRuntimeConfig(
                blockchain=BlockchainToolRuntimeConfig(**blockchain)
            )
        ),
        runtime_registry=registry,
        policy=build_blockchain_policy(data_root, metadata),
        policy_ctl=policy_ctl,
        secret_service=SimpleNamespace(
            get_secret_sync=lambda _key, *, namespace: signer_secret,
            close_sync=lambda: None,
        ),
        agent_id="abo-testnet-agent",
    )
    return ProductionBlockchainExecution(
        adapter=adapter,
        policy_ctl=policy_ctl,
        transport=request_public_https,
        approval_action="allow_once",
    )


def _load_signer_secret(payload: Mapping[str, Any], approved: Mapping[str, Any]) -> str:
    from eth_account import Account

    env_name = str(payload["signer_secret_env"])
    secret = _required(env_name)
    address = str(Account.from_key(secret).address).lower()
    if address != approved["signer_address"]:
        raise RuntimeError("signer secret does not match the approved public address")
    return secret


def _resolution_matches_approval(
    resolution: Mapping[str, Any], approved: Mapping[str, Any]
) -> None:
    data = resolution.get("data")
    if not isinstance(data, Mapping):
        raise RuntimeError(f"testnet contract resolution failed: {resolution}")
    expected = {
        "expected_chain_id": approved["expected_chain_id"],
        "observed_chain_id": approved["expected_chain_id"],
        "expected_genesis_hash": approved["expected_genesis_hash"],
        "observed_genesis_hash": approved["expected_genesis_hash"],
        "expected_checkpoint": approved["expected_checkpoint"],
        "observed_checkpoint": approved["expected_checkpoint"],
        "rpc_origin": approved["expected_rpc_origin"],
        "contract_address": approved["contract_address"],
    }
    for key, value in expected.items():
        observed = data.get(key)
        if isinstance(value, str):
            observed = str(observed).lower()
        if observed != value:
            raise RuntimeError(f"observed {key} does not match write approval")


def _resolve_and_prepare(
    execution: ProductionBlockchainExecution,
    payload: Mapping[str, Any],
    approved: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    trace_id = "abo-disposable-testnet-write"
    resolution = execution.execute_raw(
        name="blockchain.resolve_contract",
        arguments=dict(payload["resolve_request"]),
        session_id=SESSION_ID,
        trace_id=trace_id,
        invocation_id="abo-disposable-testnet-resolve",
    )["outputs"]
    if resolution.get("ok") is not True:
        raise RuntimeError(f"testnet contract resolution failed: {resolution}")
    _resolution_matches_approval(resolution, approved)
    precondition = execution.execute_raw(
        name="blockchain.inspect",
        arguments={
            **payload["precondition"],
            "action": "resolved_contract_call",
            "resolution_digest": resolution["data"]["resolution_digest"],
        },
        session_id=SESSION_ID,
        trace_id=trace_id,
        invocation_id="abo-disposable-testnet-precondition",
    )["outputs"]
    if precondition.get("ok") is not True or precondition.get("data", {}).get(
        "result"
    ) != payload["precondition"].get("expected_result"):
        raise RuntimeError("testnet precondition does not match write approval")
    preparation = execution.execute_raw(
        name="blockchain.prepare_transaction",
        arguments={
            **payload["prepare_request"],
            "kind": "resolved_contract_call",
            "resolution_digest": resolution["data"]["resolution_digest"],
        },
        session_id=SESSION_ID,
        trace_id=trace_id,
        invocation_id="abo-disposable-testnet-prepare",
    )["outputs"]
    if preparation.get("ok") is not True:
        raise RuntimeError(f"testnet transaction preparation failed: {preparation}")
    return resolution, precondition, preparation


def _send_once(
    execution: ProductionBlockchainExecution, preparation_digest: str
) -> dict[str, Any]:
    trace_id = "abo-disposable-testnet-write"
    state = WorkingState(
        session_id=SESSION_ID,
        agent_id="abo-testnet-agent",
        trace_id=trace_id,
        goal="Submit the prepared disposable testnet transaction once.",
        budgets_remaining=BudgetCounters(
            ticks=4,
            tool_calls=4,
            a2a_calls=0,
            tokens=4_000,
            time_ms=30_000,
        ),
    )
    outcome = execution.execute_command(
        state=state,
        command=ToolCommand(
            kind="tool",
            title="blockchain.send_transaction",
            tool_name="blockchain.send_transaction",
            args={"preparation_digest": preparation_digest},
            inputs={},
            idempotency_key="abo-disposable-testnet-send",
        ),
        logger=SimpleNamespace(emit=lambda *_args, **_kwargs: None),
        include_reflect=False,
    )
    return dict(outcome.action_result.outputs)


def _inspect_status(
    preparation_digest: str,
    *,
    env: EnvironmentConfig,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    return blockchain_runtime.inspect_blockchain(
        {
            "action": "operation_status",
            "preparation_digest": preparation_digest,
        },
        SimpleNamespace(session_id=SESSION_ID, env=env, metadata=metadata),
    )


def _terminal_status(
    preparation_digest: str,
    *,
    env: EnvironmentConfig,
    metadata: Mapping[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        status = _inspect_status(
            preparation_digest,
            env=env,
            metadata=metadata,
        )
        if status.get("ok") is not True:
            raise RuntimeError(f"testnet operation status failed: {status}")
        if status.get("data", {}).get("state") in TERMINAL_STATES:
            return status
        if time.monotonic() >= deadline:
            raise RuntimeError(f"testnet operation did not become terminal: {status}")
        time.sleep(2)


def _read_audit_events(data_root: Path, preparation_digest: str) -> list[dict]:
    events: list[dict] = []
    for path in sorted((data_root / "tool-runs").rglob("audit.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event.get("preparation_digest") == preparation_digest:
                events.append(event)
    return events


def _assert_retained_evidence_safe(root: Path, secrets: set[bytes]) -> None:
    retained = b"\n".join(
        path.read_bytes() for path in root.rglob("*") if path.is_file()
    )
    if any(secret and secret in retained for secret in secrets):
        raise RuntimeError("retained testnet evidence contains credential material")


def _validate_scan_attestation(
    value: object, approved: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("testnet secret-scan attestation must be an object")
    expected = {
        "schema_version": "blockchain-testnet-secret-scan-v1",
        "attempt_id": approved["attempt_id"],
        "private_root_identifier": approved["private_root_identifier"],
        "signer_address": approved["signer_address"],
        "operator_id": approved["operator_id"],
        "secret_absent": True,
    }
    if any(
        value.get(key) != expected_value for key, expected_value in expected.items()
    ):
        raise RuntimeError("testnet secret-scan attestation does not match approval")
    if value.get("source") not in {"runner_initial", "caller_recovery"}:
        raise RuntimeError("testnet secret-scan attestation source is invalid")
    if not str(value.get("scanned_at", "") or "").strip():
        raise RuntimeError("testnet secret-scan attestation time is missing")
    if set(value) != {*expected, "source", "scanned_at"}:
        raise RuntimeError("testnet secret-scan attestation fields are invalid")
    return dict(value)


def _record_initial_scan(
    approved: Mapping[str, Any], signer_secret: str
) -> dict[str, Any]:
    attempt_root = Path(approved["attempt_root"])
    _assert_retained_evidence_safe(attempt_root, {signer_secret.encode("utf-8")})
    attestation = {
        "schema_version": "blockchain-testnet-secret-scan-v1",
        "attempt_id": approved["attempt_id"],
        "private_root_identifier": approved["private_root_identifier"],
        "signer_address": approved["signer_address"],
        "operator_id": approved["operator_id"],
        "secret_absent": True,
        "source": "runner_initial",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json_atomic(attempt_root / SCAN_ATTESTATION_NAME, attestation)
    return attestation


def _required_recovery_scan(approved: Mapping[str, Any]) -> dict[str, Any]:
    attempt_root = Path(approved["attempt_root"])
    retained = attempt_root / SCAN_ATTESTATION_NAME
    if retained.is_file():
        return _validate_scan_attestation(json.loads(retained.read_bytes()), approved)
    raw_path = str(os.getenv(SCAN_ATTESTATION_ENV, "") or "").strip()
    if not raw_path:
        raise RuntimeError(
            "status-only recovery requires a caller-owned secret-scan attestation"
        )
    attestation = _validate_scan_attestation(
        json.loads(Path(raw_path).expanduser().resolve().read_bytes()),
        approved,
    )
    if attestation["source"] != "caller_recovery":
        raise RuntimeError("external recovery scan must use source=caller_recovery")
    _write_json_atomic(retained, attestation)
    return attestation


@contextmanager
def _deadline(seconds: int) -> Iterator[None]:
    if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
        raise RuntimeError("testnet write deadline is unavailable on this platform")

    def expired(_signum: int, _frame: object) -> None:
        raise TimeoutError("testnet write exceeded the approved duration")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _evidence(
    *,
    approved: Mapping[str, Any],
    manifest: Mapping[str, Any],
    status: Mapping[str, Any],
    restart_status: Mapping[str, Any],
    audit_events: list[dict],
    mutation_invocations_this_entry: int,
    send: Mapping[str, Any] | None,
    approval: Mapping[str, Any] | None,
    resolution: Mapping[str, Any] | None,
    precondition: Mapping[str, Any] | None,
    preparation: Mapping[str, Any] | None,
    retained_secret_scan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "blockchain-autonomous-testnet-write-evidence-v2",
        "protocol": "production_policy_runtime_protocol",
        "source_commit": approved["source_commit"],
        "config_sha256": approved["config_sha256"],
        "approval_envelope_digest": approved["approval_envelope_digest"],
        "private_root_identifier": approved["private_root_identifier"],
        "attempt_manifest": dict(manifest),
        "resolution": resolution,
        "precondition": precondition,
        "preparation": preparation,
        "send": send,
        "operation_status": dict(status),
        "restart_status": dict(restart_status),
        "audit_events": audit_events,
        "policy_approval": approval,
        "mutation_invocations_this_entry": mutation_invocations_this_entry,
        "mutation_invocations_total": 1,
        "max_broadcasts": 1,
        "key_deletion_attestation": None,
        "retained_secret_scan": retained_secret_scan,
        "execution_owners": {
            "command_executor": "RunnerCommandExecutor",
            "tool_adapter": "ToolAdapter",
            "policy_adapter": "PolicyCtlBrainAdapter",
            "send_scope": "POWER_USER",
        },
    }


def validate_evidence(evidence: object) -> None:
    if not isinstance(evidence, dict):
        raise ValueError("testnet evidence must be an object")
    if evidence.get("schema_version") != (
        "blockchain-autonomous-testnet-write-evidence-v2"
    ):
        raise ValueError("testnet evidence schema is missing")
    if evidence.get("protocol") != "production_policy_runtime_protocol":
        raise ValueError("testnet protocol is missing")
    for field in ("source_commit", "config_sha256", "approval_envelope_digest"):
        if not evidence.get(field):
            raise ValueError(f"testnet {field} is missing")
    manifest = evidence.get("attempt_manifest")
    if not isinstance(manifest, dict) or manifest.get("state") != "succeeded":
        raise ValueError("testnet terminal attempt manifest is missing")
    for evidence_field, manifest_field in (
        ("source_commit", "source_commit"),
        ("config_sha256", "config_sha256"),
        ("approval_envelope_digest", "approval_envelope_digest"),
        ("private_root_identifier", "private_root_identifier"),
    ):
        if evidence[evidence_field] != manifest.get(manifest_field):
            raise ValueError(f"testnet {evidence_field} does not join to manifest")
    preparation_digest = manifest.get("preparation_digest")
    for key in ("operation_status", "restart_status"):
        status = evidence.get(key, {})
        data = status.get("data", {})
        if status.get("ok") is not True or data.get("state") != "succeeded":
            raise ValueError(f"{key} is not succeeded")
        if data.get("preparation_digest") != preparation_digest:
            raise ValueError(f"{key} does not join to preparation")
        if data.get("submission_started") is not True:
            raise ValueError(f"{key} lacks submission evidence")
        if data.get("broadcast_attempts") != 1:
            raise ValueError(f"{key} does not prove one broadcast attempt")
        postconditions = data.get("postcondition_results", ())
        if not postconditions or any(
            item.get("matched") is not True for item in postconditions
        ):
            raise ValueError(f"{key} lacks matched postcondition evidence")
    if evidence.get("mutation_invocations_total") != 1:
        raise ValueError("testnet evidence must prove one mutation invocation")
    invocation_count = evidence.get("mutation_invocations_this_entry")
    if invocation_count not in {0, 1}:
        raise ValueError("testnet entry mutation count is invalid")
    if invocation_count == 1:
        approval = evidence.get("policy_approval")
        if (
            not isinstance(approval, dict)
            or approval.get("action") != "allow_once"
            or not approval.get("grant_id")
            or approval.get("preview", {}).get("preparation_digest")
            != preparation_digest
        ):
            raise ValueError("initial testnet entry lacks one-time policy approval")
    elif any(
        evidence.get(field) is not None
        for field in (
            "resolution",
            "precondition",
            "preparation",
            "send",
            "policy_approval",
        )
    ):
        raise ValueError("status-only recovery contains mutation-stage evidence")
    if evidence.get("max_broadcasts") != 1:
        raise ValueError("testnet evidence must retain the one-broadcast cap")
    audit_events = evidence.get("audit_events")
    if not isinstance(audit_events, list) or len(audit_events) != 1:
        raise ValueError("testnet exact mutation audit evidence is missing")
    if audit_events[0].get("preparation_digest") != preparation_digest:
        raise ValueError("testnet mutation audit does not join to preparation")
    if evidence.get("key_deletion_attestation") is not None:
        raise ValueError("runner cannot attest caller-owned key deletion")
    scan = evidence.get("retained_secret_scan")
    if not isinstance(scan, dict):
        raise ValueError("testnet retained-secret scan evidence is missing")
    if (
        scan.get("schema_version") != "blockchain-testnet-secret-scan-v1"
        or scan.get("attempt_id") != manifest.get("attempt_id")
        or scan.get("private_root_identifier")
        != manifest.get("private_root_identifier")
        or scan.get("signer_address") != manifest.get("signer_address")
        or scan.get("secret_absent") is not True
        or scan.get("source") not in {"runner_initial", "caller_recovery"}
        or not str(scan.get("operator_id", "") or "").strip()
        or not str(scan.get("scanned_at", "") or "").strip()
    ):
        raise ValueError("testnet retained-secret scan does not join to attempt")
    if evidence.get("execution_owners") != {
        "command_executor": "RunnerCommandExecutor",
        "tool_adapter": "ToolAdapter",
        "policy_adapter": "PolicyCtlBrainAdapter",
        "send_scope": "POWER_USER",
    }:
        raise ValueError("testnet production execution owners are missing")


def _run_initial(
    payload: dict[str, Any], approved: dict[str, Any], signer_secret: str
) -> dict[str, Any]:
    attempt_root = Path(approved["attempt_root"])
    metadata = _metadata(payload)
    with _configured_runtime(attempt_root) as env:
        execution = _execution(attempt_root, metadata, signer_secret)
        send: dict[str, Any] | None = None
        send_error: Exception | None = None
        try:
            resolution, precondition, preparation = _resolve_and_prepare(
                execution, payload, approved
            )
            _write_manifest(
                approved,
                state="prepared",
                preparation_digest=preparation["preparation_digest"],
            )
            try:
                send = _send_once(execution, preparation["preparation_digest"])
            except Exception as exc:
                send_error = exc
            approval = execution.approval
        finally:
            execution.close()
        operation = _load_operation(preparation["preparation_digest"], env)
        if operation is None:
            _write_manifest(
                approved,
                state="not_submitted",
                preparation_digest=preparation["preparation_digest"],
            )
            if send_error is not None:
                raise RuntimeError(
                    "testnet send did not create an operation record"
                ) from send_error
            raise RuntimeError("testnet send did not create an operation record")
        _write_manifest(
            approved,
            state=str(operation["state"]),
            preparation_digest=preparation["preparation_digest"],
        )
        status_metadata = _status_metadata(approved)
        status = _terminal_status(
            preparation["preparation_digest"],
            env=env,
            metadata=status_metadata,
            timeout_seconds=float(approved["max_duration_seconds"]),
        )
        restart_status = _inspect_status(
            preparation["preparation_digest"],
            env=env,
            metadata=status_metadata,
        )
        manifest = _write_manifest(
            approved,
            state=str(status["data"]["state"]),
            preparation_digest=preparation["preparation_digest"],
        )
        evidence = _evidence(
            approved=approved,
            manifest=manifest,
            status=status,
            restart_status=restart_status,
            audit_events=_read_audit_events(
                Path(env.openminion_data_root), preparation["preparation_digest"]
            ),
            mutation_invocations_this_entry=1,
            send=send,
            approval=approval,
            resolution=resolution,
            precondition=precondition,
            preparation=preparation,
        )
    return evidence


def _run_recovery(approved: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    env = _runtime_env(Path(approved["attempt_root"]))
    metadata = _status_metadata(approved)
    preparation_digest = manifest["preparation_digest"]
    status = _terminal_status(
        preparation_digest,
        env=env,
        metadata=metadata,
        timeout_seconds=float(approved["max_duration_seconds"]),
    )
    restart_status = _inspect_status(
        preparation_digest,
        env=env,
        metadata=metadata,
    )
    manifest = _write_manifest(
        approved,
        state=str(status["data"]["state"]),
        preparation_digest=preparation_digest,
    )
    return _evidence(
        approved=approved,
        manifest=manifest,
        status=status,
        restart_status=restart_status,
        audit_events=_read_audit_events(
            Path(env.openminion_data_root), preparation_digest
        ),
        mutation_invocations_this_entry=0,
        send=None,
        approval=None,
        resolution=None,
        precondition=None,
        preparation=None,
    )


def main() -> int:
    if os.getenv(OPT_IN) != "1":
        raise RuntimeError(f"{OPT_IN}=1 is required")
    config_path, payload, config_sha256 = _required_config()
    approved = _approved_attempt(config_path, payload, config_sha256)
    attempt_root = Path(approved["attempt_root"])
    signer_secret: str | None = None
    scan_attestation: dict[str, Any] | None = None
    try:
        with _deadline(int(approved["max_duration_seconds"])):
            if attempt_root.exists():
                if stat.S_IMODE(attempt_root.stat().st_mode) & 0o077:
                    raise RuntimeError("attempt root must be owner-only")
                manifest = _resume_manifest(approved)
                evidence = _run_recovery(approved, manifest)
            else:
                signer_secret = _load_signer_secret(payload, approved)
                attempt_root.mkdir(mode=0o700)
                evidence = _run_initial(payload, approved, signer_secret)
    finally:
        if signer_secret is not None and attempt_root.exists():
            scan_attestation = _record_initial_scan(approved, signer_secret)
    if scan_attestation is None:
        scan_attestation = _required_recovery_scan(approved)
    evidence["retained_secret_scan"] = scan_attestation
    _assert_approval_unchanged(approved)
    validate_evidence(evidence)
    _write_json_atomic(attempt_root / EVIDENCE_NAME, evidence)
    if signer_secret is not None:
        _assert_retained_evidence_safe(
            attempt_root,
            {signer_secret.encode("utf-8")},
        )
    _assert_approval_unchanged(approved)
    print(f"ABO testnet write PASS evidence={attempt_root / EVIDENCE_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
