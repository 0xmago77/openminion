from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner
import yaml

from openminion.modules.memory.cli import _build_app
from openminion.modules.memory.config import (
    MEMCTL_CONFIG_ENV,
    ConfigError,
    MemctlConfig,
    load_config,
)
from openminion.modules.memory.errors import InvalidArgumentError
from openminion.modules.memory.runtime.remote_transport import (
    RemoteMemoryStore,
    RemoteMemoryTransport,
)
from openminion.modules.memory.storage.factory import (
    ResolvedMemoryBackend,
    resolve_memory_backend,
)

ENDPOINT = "https://memory.example/v1"
MISSING_ENDPOINT = "remote backend requires remote.endpoint"


def _write_remote_config(tmp_path: Path, remote: dict[str, Any]) -> Path:
    path = tmp_path / "memctl.yaml"
    memctl = {
        "store": {"backend": "remote", "remote": remote},
        "defaults": {"confidence": {"user_said": 0.7}},
        "promotion": {},
        "retrieval": {},
        "retention": {},
    }
    path.write_text(yaml.safe_dump({"version": 1, "memctl": memctl}), encoding="utf-8")
    return path


def _load_remote_config(
    tmp_path: Path, *, timeout_seconds: float = 2.5, max_retries: int = 2
) -> MemctlConfig:
    remote = {
        "endpoint": ENDPOINT,
        "timeout_seconds": timeout_seconds,
        "max_retries": max_retries,
    }
    return load_config(
        _write_remote_config(tmp_path, remote), env={"HOME": str(tmp_path)}
    )


def _transport_settings(resolved: ResolvedMemoryBackend) -> tuple[Any, ...]:
    assert resolved.backend == "remote"
    assert isinstance(resolved.store, RemoteMemoryStore)
    assert resolved.capabilities.supports_transactions is False
    transport = resolved.store._transport
    return (
        transport._endpoint,
        transport._timeout_seconds,
        transport._max_retries,
        transport._auth_token,
    )


@pytest.mark.parametrize("shape", ["whole-config", "store-section"])
@pytest.mark.parametrize(("timeout_seconds", "max_retries"), [(2.5, 2), (0.5, 0)])
def test_parsed_config_selects_remote_backend_with_its_transport_values(
    tmp_path: Path, shape: str, timeout_seconds: float, max_retries: int
) -> None:
    parsed = _load_remote_config(
        tmp_path, timeout_seconds=timeout_seconds, max_retries=max_retries
    )
    config = parsed if shape == "whole-config" else parsed.store

    resolved = resolve_memory_backend(config=config, db_path=tmp_path / "unused.db")

    assert _transport_settings(resolved) == (ENDPOINT, timeout_seconds, max_retries, "")


@pytest.mark.parametrize("nested_under_store", [True, False])
def test_equivalent_dict_config_resolves_the_same_transport(
    tmp_path: Path, nested_under_store: bool
) -> None:
    parsed = _load_remote_config(tmp_path)
    remote = {"endpoint": ENDPOINT, "timeout_seconds": 2.5, "max_retries": 2}
    config: dict[str, Any] = (
        {"store": {"backend": "remote", "remote": remote}}
        if nested_under_store
        else {"backend": "remote", "remote": remote}
    )

    from_dict = resolve_memory_backend(config=config, db_path=tmp_path / "a.db")
    from_parsed = resolve_memory_backend(config=parsed, db_path=tmp_path / "b.db")

    assert _transport_settings(from_dict) == (ENDPOINT, 2.5, 2, "")
    assert _transport_settings(from_parsed) == _transport_settings(from_dict)


def test_dict_config_keeps_its_defaults_and_auth_token(tmp_path: Path) -> None:
    resolved = resolve_memory_backend(
        config={
            "store": {
                "backend": "remote",
                "remote": {"endpoint": f" {ENDPOINT} ", "auth_token": "dict-token"},
            }
        },
        db_path=tmp_path / "unused.db",
    )

    assert _transport_settings(resolved) == (ENDPOINT, 5.0, 1, "dict-token")


def test_nested_remote_mapping_takes_precedence_over_typed_fields(
    tmp_path: Path,
) -> None:
    parsed = _load_remote_config(tmp_path)
    nested_endpoint = "https://nested.example/v1"
    config = SimpleNamespace(remote={"endpoint": nested_endpoint}, store=parsed.store)

    resolved = resolve_memory_backend(config=config, db_path=tmp_path / "unused.db")

    # The nested mapping is used as a whole: no timeout or retries from the typed
    # fields, so the mapping's own defaults apply.
    assert _transport_settings(resolved) == (nested_endpoint, 5.0, 1, "")


def test_missing_endpoint_keeps_the_error(tmp_path: Path) -> None:
    parsed = _load_remote_config(tmp_path)
    typed_store = replace(parsed.store, remote_endpoint="")
    configs: list[Any] = [
        typed_store,
        replace(parsed, store=typed_store),
        {"store": {"backend": "remote"}},
        {"store": {"backend": "remote", "remote": {"timeout_seconds": 2.5}}},
        {"backend": "remote", "remote": {"endpoint": "  "}},
    ]

    for config in configs:
        with pytest.raises(InvalidArgumentError, match=MISSING_ENDPOINT):
            resolve_memory_backend(config=config, db_path=tmp_path / "unused.db")

    with pytest.raises(ConfigError, match="store.remote.endpoint is required"):
        load_config(
            _write_remote_config(tmp_path, {"timeout_seconds": 2.5}),
            env={"HOME": str(tmp_path)},
        )


@pytest.mark.parametrize("runtime_roots", [True, False])
def test_memctl_uses_the_remote_store_from_memctl_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime_roots: bool
) -> None:
    config_path = _write_remote_config(
        tmp_path, {"endpoint": ENDPOINT, "timeout_seconds": 2.5, "max_retries": 2}
    )
    monkeypatch.setenv(MEMCTL_CONFIG_ENV, str(config_path))
    if not runtime_roots:
        monkeypatch.delenv("OPENMINION_HOME", raising=False)
        monkeypatch.delenv("OPENMINION_DATA_ROOT", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
    sent: list[tuple[Any, ...]] = []

    def _record_without_network(
        transport: RemoteMemoryTransport,
        envelope: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        sent.append(
            (
                envelope["operation"],
                transport._endpoint,
                timeout_seconds,
                transport._max_retries,
            )
        )
        return {"ok": True, "data": {"records": []}}

    monkeypatch.setattr(RemoteMemoryTransport, "_http_sender", _record_without_network)

    result = CliRunner().invoke(
        _build_app(), ["list", "--scope", "agent:alpha", "--json"]
    )

    assert result.exit_code == 0, repr(result.exception)
    assert json.loads(result.stdout) == []
    assert sent == [("list", ENDPOINT, 2.5, 2)]
