"""The runtime disposes the PostgreSQL engine its memory assembly creates.

With the `external` memory backend provider the assembly creates no memory
store, so a PostgreSQL store config opens no engine at all.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import event

from openminion import Agent, APIRuntime
from openminion.base.channel import ChannelRegistry
from openminion.base.config import ConfigManager, OpenMinionConfig, save_config
from openminion.modules.memory.backends.external import (
    REFERENCE_SQLITE_ADAPTER_NAME,
    register_reference_sqlite_backend,
)
from openminion.modules.memory.config import from_base_config
from openminion.modules.memory.models import MemoryRecord
from openminion.modules.memory.storage import AuditedMemoryStore
from openminion.modules.memory.storage.postgres.store import PostgresMemoryStore
from openminion.modules.storage.runtime.idempotency_store import IdempotencyStore
from openminion.modules.storage.runtime.migrations import migrate_database
from openminion.modules.storage.runtime.session_store import SessionStore
from openminion.modules.storage.runtime.sqlite import connect_database
from openminion.services.runtime import memory as runtime_memory
from openminion.services.runtime.bootstrap import (
    build_agent_memory_service,
    build_gateway_service,
)
from tests._csc_fixtures import _csc_install_default_agent
from tests.storage.postgres_test_utils import schema_url

pytestmark = pytest.mark.postgres


@pytest.fixture
def memory_database() -> Iterator[tuple[str, Callable[[], int]]]:
    postgres_url = str(os.getenv("OPENMINION_TEST_POSTGRES_URL", "")).strip()
    if not postgres_url:
        pytest.skip("OPENMINION_TEST_POSTGRES_URL is not set")
    token = uuid.uuid4().hex[:12]
    schema_name = f"runtime_memory_{token}"
    application_name = f"om_runtime_memory_{token}"
    admin_engine = sa.create_engine(postgres_url, future=True)
    with admin_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema_name}"'))

    def server_connections() -> int:
        with admin_engine.connect() as conn:
            return conn.execute(
                sa.text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE application_name = :name"
                ),
                {"name": application_name},
            ).scalar_one()

    url = f"{schema_url(postgres_url, schema_name)}&application_name={application_name}"
    try:
        yield url, server_connections
    finally:
        with admin_engine.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
        admin_engine.dispose()


def _settled_connections(server_connections: Callable[[], int]) -> int:
    deadline = time.monotonic() + 5.0
    count = server_connections()
    while count and time.monotonic() < deadline:
        time.sleep(0.05)
        count = server_connections()
    return count


def _memory_runtime(root: Path, memory_config: Callable[..., object]) -> APIRuntime:
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider="echo")
    config.runtime.process_mode = "single-process"
    config.runtime.daemon_auto_start = False
    config.storage.path = str(root / ".openminion" / "state.db")
    config_path = root / "agents.json"
    save_config(config, str(config_path))
    manager = ConfigManager.load(
        str(config_path), home_root=root, data_root=root / ".openminion"
    )
    manager.register("memory", memory_config)
    return APIRuntime.from_manager(manager)


def _postgres_memory_runtime(root: Path, memory_url: str) -> APIRuntime:
    def postgres_memory_config(**kwargs):
        memory_config = from_base_config(**kwargs)
        store = dataclasses.replace(
            memory_config.store, backend="postgres", postgres_url=memory_url
        )
        return dataclasses.replace(memory_config, store=store)

    return _memory_runtime(root, postgres_memory_config)


def test_runtime_close_disposes_the_postgres_memory_engine_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    memory_database: tuple[str, Callable[[], int]],
) -> None:
    memory_url, server_connections = memory_database
    stores: list[object] = []
    disposed: list[object] = []
    resolve_backend = runtime_memory.resolve_memory_backend

    def record_backend(**kwargs):
        resolved = resolve_backend(**kwargs)
        event.listen(resolved.store._engine, "engine_disposed", disposed.append)
        stores.append(resolved.store)
        return resolved

    monkeypatch.setattr(runtime_memory, "resolve_memory_backend", record_backend)

    runtime = _postgres_memory_runtime(tmp_path / "root", memory_url)
    try:
        with Agent(runtime=runtime) as agent:
            assert agent.run("hello").run_state == "completed"
        open_after_turn = server_connections()
        dispose_counts: list[int] = []
        for _ in range(2):
            runtime.close()
            dispose_counts.append(len(disposed))
        open_after_close = _settled_connections(server_connections)
    finally:
        runtime.close()
        for store in stores:
            store._engine.dispose()

    assert [type(store) for store in stores] == [PostgresMemoryStore]
    assert open_after_turn >= 1
    assert dispose_counts == [1, 1]
    assert open_after_close == 0


class _ReplyAgent:
    async def run_turn(self, message, history=None, **_kwargs):  # noqa: ANN001
        del history, _kwargs
        return SimpleNamespace(
            text="Noted.", channel=message.channel, target=message.target, metadata={}
        )


@pytest.mark.parametrize("owner", ["gateway", "caller"])
def test_bootstrap_memory_fallback_owner_disposes_the_postgres_engine_once(
    owner: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    memory_database: tuple[str, Callable[[], int]],
) -> None:
    memory_url, server_connections = memory_database
    stores: list[object] = []
    disposed: list[object] = []
    resolve_backend = runtime_memory.resolve_memory_backend

    def record_backend(**kwargs):
        resolved = resolve_backend(**kwargs)
        event.listen(resolved.store._engine, "engine_disposed", disposed.append)
        stores.append(resolved.store)
        return resolved

    monkeypatch.setattr(runtime_memory, "resolve_memory_backend", record_backend)
    root = tmp_path / "root"
    config = OpenMinionConfig()
    _csc_install_default_agent(config, name="main", provider="echo")
    config_path = root / "agents.json"
    save_config(config, str(config_path))
    manager = ConfigManager.load(
        str(config_path), home_root=root, data_root=root / "data"
    )
    memory_config = {"store": {"backend": "postgres", "postgres": {"url": memory_url}}}
    manager.register("memory", lambda **kwargs: memory_config)
    database_path = root / "state" / "openminion.db"
    migrate_database(database_path)
    connection = connect_database(database_path)
    common = {
        "config": config,
        "memory_root": root / "memory",
        "home_root": root,
        "data_root": root / "data",
        "config_manager": manager,
        "logger": logging.getLogger("test.runtime_memory_postgres.fallback"),
    }
    try:
        if owner == "gateway":
            closer = build_gateway_service(
                agent_service=_ReplyAgent(),
                profile_name="main",
                channels=ChannelRegistry([]),
                sessions=SessionStore(connection),
                idempotency=IdempotencyStore(connection),
                security_policy=None,
                channel_authenticity_policy=None,
                config_path=config_path,
                storage_path=database_path,
                **common,
            )
            asyncio.run(
                closer.run_once(
                    channel="console",
                    target="local-user",
                    message="Remember: the probe colour is green.",
                    session_id="s1",
                    deliver=False,
                )
            )
        else:
            closer = build_agent_memory_service(
                agent_id="main", storage_path=database_path, **common
            )
            closer.record_turn(
                session_id="s1",
                run_id="r1",
                request_id="q1",
                channel="console",
                target="local-user",
                user_message="Remember: the probe colour is green.",
                assistant_message="Noted.",
            )
        open_after_turn = server_connections()
        dispose_counts: list[int] = []
        for _ in range(2):
            closer.close()
            dispose_counts.append(len(disposed))
        open_after_close = _settled_connections(server_connections)
    finally:
        connection.close()
        for store in stores:
            store._engine.dispose()

    assert [type(store) for store in stores] == [PostgresMemoryStore]
    assert open_after_turn >= 1
    assert dispose_counts == [1, 1]
    assert open_after_close == 0


def test_audited_store_leaves_a_borrowed_postgres_store_open(
    tmp_path: Path,
    memory_database: tuple[str, Callable[[], int]],
) -> None:
    memory_url, server_connections = memory_database
    engine = sa.create_engine(memory_url, future=True)
    disposed: list[object] = []
    event.listen(engine, "engine_disposed", disposed.append)
    store = PostgresMemoryStore(
        engine,
        database_path=tmp_path / "memory.db",
        artifactctl=None,
        owns_engine=True,
    )
    try:
        audited = AuditedMemoryStore(store)
        record_id = audited.put(
            MemoryRecord(
                id="borrowed-r1",
                scope="session:s1",
                type="fact",
                title="borrowed",
                content={"text": "borrowed store"},
                created_at="2026-10-24T00:00:00+00:00",
                updated_at="2026-10-24T00:00:00+00:00",
            )
        )

        audited.close()
        audited.close()

        assert disposed == []
        assert server_connections() >= 1
        assert store.get(record_id) is not None

        store.close()
        store.close()

        assert len(disposed) == 1
        assert _settled_connections(server_connections) == 0
    finally:
        engine.dispose()


def test_external_memory_provider_opens_no_postgres_memory_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    memory_database: tuple[str, Callable[[], int]],
) -> None:
    memory_url, server_connections = memory_database
    stores: list[object] = []
    resolve_backend = runtime_memory.resolve_memory_backend

    def record_backend(**kwargs):
        resolved = resolve_backend(**kwargs)
        stores.append(resolved.store)
        return resolved

    monkeypatch.setattr(runtime_memory, "resolve_memory_backend", record_backend)
    register_reference_sqlite_backend()
    root = tmp_path / "root"
    memory_config = {
        "store": {"backend": "postgres", "postgres": {"url": memory_url}},
        "backend": {
            "provider": "external",
            "external_adapter": REFERENCE_SQLITE_ADAPTER_NAME,
            "options": {"db_path": str(root / "external.sqlite3")},
        },
    }

    runtime = _memory_runtime(root, lambda **kwargs: memory_config)
    try:
        open_after_build = server_connections()
        runtime.close()
        runtime.close()
        open_after_close = _settled_connections(server_connections)
    finally:
        runtime.close()
        for store in stores:
            store._engine.dispose()

    assert [type(store) for store in stores] == []
    assert open_after_build == 0
    assert open_after_close == 0
