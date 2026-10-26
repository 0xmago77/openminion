"""SDK artifact stores stay inside each runtime's explicit roots and close with it."""

import hashlib
from pathlib import Path

import pytest

from sophiagraph.storage import SophiaGraphSqliteStore

from openminion import Agent, APIRuntime
from openminion.base.config import ConfigManager, OpenMinionConfig, save_config
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.memory.backends.external import (
    REFERENCE_SQLITE_ADAPTER_NAME,
    register_external_backend,
    register_reference_sqlite_backend,
)
from openminion.modules.memory.runtime.assembly import RuntimeMemoryAssembly
from openminion.modules.memory.storage.audit import SQLiteMemoryAuditSink
from openminion.modules.memory.storage.sqlite.store import SQLiteMemoryStore
from openminion.services.runtime import memory as runtime_memory
from tests._csc_fixtures import _csc_install_default_agent

_ALIAS = "shared-note"
_OVERRIDE_ENV_KEYS = (
    "OPENMINION_HOME",
    "OPENMINION_DATA_ROOT",
    "OPENMINION_GENERATED_ROOT",
    "OPENMINION_CONFIG_PATH",
)


def _artifact_index(root: Path) -> Path:
    return (root / ".openminion" / "artifact" / "index.db").resolve()


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _echo_runtime(root: Path, memory_config: dict | None = None) -> APIRuntime:
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider="echo")
    config.runtime.process_mode = "single-process"
    config.runtime.daemon_auto_start = False
    config.storage.path = str(root / ".openminion" / "state.db")
    config_path = root / "agents.json"
    save_config(config, str(config_path))
    if memory_config is None:
        return APIRuntime.from_config_path(
            str(config_path), home_root=root, data_root=root / ".openminion"
        )
    manager = ConfigManager.load(
        str(config_path), home_root=root, data_root=root / ".openminion"
    )
    manager.register("memory", lambda **kwargs: memory_config)
    return APIRuntime.from_manager(manager)


@pytest.fixture
def unrelated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    for key in _OVERRIDE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(home)
    with ArtifactCtl({}) as store:
        ref = store.ingest_bytes(b"UNRELATED_ARTIFACT")
        store.alias_set(_ALIAS, ref.sha256)
    assert _artifact_index(home).is_file()
    return home


def test_sdk_artifact_reads_and_writes_stay_in_runtime_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unrelated_home: Path,
) -> None:
    home_before = _snapshot(unrelated_home)
    opened: list[Path] = []
    original_init = ArtifactCtl.__init__

    def record_index(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        opened.append(Path(self.config.index.sqlite_path).resolve())

    monkeypatch.setattr(ArtifactCtl, "__init__", record_index)

    root_a = tmp_path / "root-a"
    root_b = tmp_path / "root-b"
    runtimes = {"a": _echo_runtime(root_a), "b": _echo_runtime(root_b)}
    written: dict[str, str] = {}
    read_back: dict[str, bytes] = {}
    listed: dict[str, set[str]] = {}
    try:
        for name, runtime in runtimes.items():
            with Agent(runtime=runtime, session_id=f"artifact-{name}") as agent:
                assert agent.run("hello").run_state == "completed"
            store = runtime.agent.artifactctl
            assert store.alias_resolve(_ALIAS) is None
            written[name] = store.ingest_bytes(f"ROOT_{name}_ARTIFACT".encode()).sha256
            store.alias_set(_ALIAS, written[name])
        for name, runtime in runtimes.items():
            store = runtime.agent.artifactctl
            read_back[name] = store.read_bytes(store.alias_resolve(_ALIAS).sha256)
            listed[name] = {meta.sha256 for meta in store.list_recent(limit=500)}
    finally:
        for runtime in runtimes.values():
            runtime.close()

    unrelated_sha = hashlib.sha256(b"UNRELATED_ARTIFACT").hexdigest()
    assert read_back == {"a": b"ROOT_a_ARTIFACT", "b": b"ROOT_b_ARTIFACT"}
    assert written["a"] in listed["a"] and written["b"] not in listed["a"]
    assert written["b"] in listed["b"] and written["a"] not in listed["b"]
    assert unrelated_sha not in listed["a"] | listed["b"]
    assert set(opened) == {_artifact_index(root_a), _artifact_index(root_b)}
    assert _snapshot(unrelated_home) == home_before


def test_runtime_close_closes_each_runtime_artifact_store_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[ArtifactCtl] = []
    closed: list[int] = []
    memory_stores: list[ArtifactCtl] = []
    original_init, original_close = ArtifactCtl.__init__, ArtifactCtl.close
    create_memory_store = runtime_memory.create_default_artifactctl

    def record_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created.append(self)

    def record_close(self):
        closed.append(id(self))
        original_close(self)

    def record_memory_store(config=None):
        store = create_memory_store(config)
        memory_stores.append(store)
        return store

    monkeypatch.setattr(ArtifactCtl, "__init__", record_init)
    monkeypatch.setattr(ArtifactCtl, "close", record_close)
    monkeypatch.setattr(
        runtime_memory, "create_default_artifactctl", record_memory_store
    )

    runtime = _echo_runtime(tmp_path / "root")
    try:
        with Agent(runtime=runtime) as agent:
            assert agent.run("hello").run_state == "completed"
        runtime.close()
        runtime.close()
        close_counts = [closed.count(id(store)) for store in created]
    finally:
        runtime.close()
        for store in created:
            if id(store) not in closed:
                original_close(store)

    assert len(memory_stores) == 1
    assert created[0] is memory_stores[0]
    assert close_counts == [1, 1, 1]


def test_runtime_close_closes_the_memory_audit_sink_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[SQLiteMemoryAuditSink] = []
    closed: list[int] = []
    memory_sinks: list[SQLiteMemoryAuditSink] = []
    original_init = SQLiteMemoryAuditSink.__init__
    original_close = SQLiteMemoryAuditSink.close
    create_memory_sink = runtime_memory.SQLiteMemoryAuditSink

    def record_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created.append(self)

    def record_close(self):
        closed.append(id(self))
        original_close(self)

    def record_memory_sink(db_path):
        sink = create_memory_sink(db_path)
        memory_sinks.append(sink)
        return sink

    monkeypatch.setattr(SQLiteMemoryAuditSink, "__init__", record_init)
    monkeypatch.setattr(SQLiteMemoryAuditSink, "close", record_close)
    monkeypatch.setattr(runtime_memory, "SQLiteMemoryAuditSink", record_memory_sink)

    runtime = _echo_runtime(tmp_path / "root")
    try:
        with Agent(runtime=runtime) as agent:
            assert agent.run("hello").run_state == "completed"
        open_after_turn = [sink._conn is not None for sink in created]
        close_counts: list[list[int]] = []
        for _ in range(2):
            runtime.close()
            close_counts.append([closed.count(id(sink)) for sink in created])
        open_after_close = [sink._conn is not None for sink in created]
    finally:
        runtime.close()
        for sink in created:
            original_close(sink)

    assert created == memory_sinks
    assert len(created) == 1
    assert open_after_turn == [True]
    assert close_counts == [[1], [1]]
    assert open_after_close == [False]


def test_runtime_close_closes_the_memory_store_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stores: list[object] = []
    closed: list[int] = []
    original_close = SQLiteMemoryStore.close
    resolve_backend = runtime_memory.resolve_memory_backend

    def record_close(self):
        closed.append(id(self))
        original_close(self)

    def record_backend(**kwargs):
        resolved = resolve_backend(**kwargs)
        stores.append(resolved.store)
        return resolved

    monkeypatch.setattr(SQLiteMemoryStore, "close", record_close)
    monkeypatch.setattr(runtime_memory, "resolve_memory_backend", record_backend)

    runtime = _echo_runtime(tmp_path / "root")
    try:
        with Agent(runtime=runtime) as agent:
            assert agent.run("hello").run_state == "completed"
        close_counts: list[list[int]] = []
        for _ in range(2):
            runtime.close()
            close_counts.append([closed.count(id(store)) for store in stores])
    finally:
        runtime.close()

    assert [type(store) for store in stores] == [SQLiteMemoryStore]
    assert close_counts == [[1], [1]]


class _ClosingReferenceBackend(SophiaGraphSqliteStore):
    def __init__(self, db_path: Path, closed: list[int]) -> None:
        super().__init__(db_path)
        self.closed = closed

    def close(self) -> None:
        self.closed.append(id(self))


@pytest.mark.parametrize("closes", [True, False], ids=["backend_close", "no_close"])
def test_runtime_close_closes_the_external_memory_backend_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closes: bool,
) -> None:
    backend_closes: list[int] = []
    artifact_closes: list[int] = []
    memory_artifact_stores: list[ArtifactCtl] = []
    created_stores: list[object] = []
    outcomes: list[str] = []
    original_artifact_close = ArtifactCtl.close
    original_assembly_close = RuntimeMemoryAssembly.close
    create_memory_artifact_store = runtime_memory.create_default_artifactctl
    resolve_backend = runtime_memory.resolve_memory_backend

    register_reference_sqlite_backend()
    adapter = REFERENCE_SQLITE_ADAPTER_NAME
    if closes:
        adapter = "closing-reference-sqlite"
        register_external_backend(
            adapter,
            factory=lambda *, config, **_: _ClosingReferenceBackend(
                Path(config.options["db_path"]), backend_closes
            ),
        )

    def record_artifact_close(self):
        artifact_closes.append(id(self))
        original_artifact_close(self)

    def record_memory_artifact_store(config=None):
        store = create_memory_artifact_store(config)
        memory_artifact_stores.append(store)
        return store

    def record_backend(**kwargs):
        resolved = resolve_backend(**kwargs)
        created_stores.append(resolved.store)
        return resolved

    def record_assembly_close(self):
        try:
            result = original_assembly_close(self)
        except Exception as exc:
            outcomes.append(f"{type(exc).__name__}: {exc}")
            raise
        outcomes.append(result.reason_code)
        return result

    monkeypatch.setattr(ArtifactCtl, "close", record_artifact_close)
    monkeypatch.setattr(
        runtime_memory, "create_default_artifactctl", record_memory_artifact_store
    )
    monkeypatch.setattr(runtime_memory, "resolve_memory_backend", record_backend)
    monkeypatch.setattr(RuntimeMemoryAssembly, "close", record_assembly_close)

    root = tmp_path / "root"
    runtime = _echo_runtime(
        root,
        {
            "backend": {
                "provider": "external",
                "external_adapter": adapter,
                "options": {"db_path": str(root / "external.sqlite3")},
            }
        },
    )
    try:
        [memory_artifact_store] = memory_artifact_stores
        close_counts: list[tuple[int, int]] = []
        for _ in range(2):
            runtime.close()
            close_counts.append(
                (artifact_closes.count(id(memory_artifact_store)), len(backend_closes))
            )
    finally:
        runtime.close()
        for store in memory_artifact_stores:
            if id(store) not in artifact_closes:
                original_artifact_close(store)

    assert outcomes == ["closed"]
    assert close_counts == [(1, int(closes)), (1, int(closes))]
    assert created_stores == []
