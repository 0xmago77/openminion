from __future__ import annotations

import logging

import pytest

from openminion.base.config import OpenMinionConfig
from openminion.modules.brain.adapters.memory.runtime import MemctlAdapter
from openminion.modules.memory.smoke import EphemeralMemorySmokeProvider
from openminion.services.agent.memory.gateway_adapter import (
    DisabledMemoryGatewayAdapter,
)
from openminion.services.runtime.memory import (
    RuntimeMemoryAssembly,
    active_runtime_memory_assembly,
    build_memory_v2_runtime_assembly,
    build_runtime_memory_assembly,
)


class _Service:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def close(self) -> None:
        self.events.append("service.close")


class _ArtifactStore:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = [] if events is None else events

    def close(self) -> None:
        self.events.append("artifactctl.close")


class _FailingArtifactStore(_ArtifactStore):
    def close(self) -> None:
        super().close()
        raise OSError("artifact index locked")


def _unavailable_artifact_store() -> None:
    raise OSError("artifact root unavailable")


def _memory_v2_assembly(tmp_path, **overrides) -> RuntimeMemoryAssembly:
    config = OpenMinionConfig()
    config.runtime.memory_enabled = True
    config.runtime.memory_provider = "memory_v2"
    arguments = {
        "config": config,
        "agent_id": "alpha",
        "memory_root": tmp_path,
        "logger": logging.getLogger("test.memory.artifact"),
        "config_manager": None,
        "home_root": None,
        "data_root": None,
        "session_context": None,
        "retrieve_ctl": None,
        "storage_path": None,
    }
    return build_memory_v2_runtime_assembly(**{**arguments, **overrides})


class _Scheduler:
    def __init__(self, events: list[str], *, live_after_stop: bool = False) -> None:
        self.events = events
        self.live = live_after_stop
        self.record_source = None

    def bind_record_source(self, record_source) -> None:
        self.events.append("scheduler.bind")
        self.record_source = record_source

    def start(self) -> None:
        self.events.append("scheduler.start")

    def stop(self) -> None:
        self.events.append("scheduler.stop")

    def is_alive(self) -> bool:
        return self.live


class _SnapshotVectorAdapter:
    def __init__(self) -> None:
        self.source = None
        self.snapshot = None

    def bind_record_source(self, source) -> None:
        self.source = source

    def sync_pending_records(self) -> int:
        self.snapshot = self.source.vector_sync_snapshot()
        return len(self.snapshot["current"])


class _BindingScheduler(_Scheduler):
    def __init__(self, events: list[str], adapter: _SnapshotVectorAdapter) -> None:
        super().__init__(events)
        self.adapter = adapter

    def bind_record_source(self, record_source) -> None:
        super().bind_record_source(record_source)
        self.adapter.bind_record_source(record_source)


def test_active_assembly_owns_one_non_duplicated_runtime(tmp_path) -> None:
    config = OpenMinionConfig()
    config.runtime.memory_enabled = True
    config.runtime.memory_provider = "memory_v2"

    assembly = build_memory_v2_runtime_assembly(
        config=config,
        agent_id="alpha",
        memory_root=tmp_path,
        logger=logging.getLogger("test.memory.assembly"),
        config_manager=None,
        home_root=None,
        data_root=None,
        session_context=None,
        retrieve_ctl=None,
        storage_path=None,
        artifactctl_factory=lambda: None,
    )

    assert assembly.gateway is not None
    assert assembly.service is not None
    assert isinstance(assembly.memctl, MemctlAdapter)
    assert assembly.memctl._backend is assembly.service
    assert assembly.gateway._service is assembly.service
    assert assembly.close().closed is True


def test_default_artifact_store_uses_runtime_artifact_config(
    tmp_path, monkeypatch, fresh_config_manager
) -> None:
    configs: list[object] = []
    monkeypatch.setattr(
        "openminion.services.runtime.memory.create_default_artifactctl",
        lambda config=None: configs.append(config),
    )
    config = OpenMinionConfig()
    config.runtime.memory_enabled = True
    config.runtime.memory_provider = "memory_v2"

    assembly = build_memory_v2_runtime_assembly(
        config=config,
        agent_id="alpha",
        memory_root=tmp_path,
        logger=logging.getLogger("test.memory.assembly"),
        config_manager=fresh_config_manager,
        home_root=fresh_config_manager.home_root,
        data_root=fresh_config_manager.data_root,
        session_context=None,
        retrieve_ctl=None,
        storage_path=None,
    )
    assembly.close()

    assert configs == [fresh_config_manager.get("artifact")]


@pytest.mark.parametrize("source", ["default", "factory"])
def test_assembly_closes_artifact_store_it_obtains_once(
    tmp_path, monkeypatch, source
) -> None:
    store = _ArtifactStore()
    overrides: dict[str, object] = {}
    if source == "default":
        monkeypatch.setattr(
            "openminion.services.runtime.memory.create_default_artifactctl",
            lambda config=None: store,
        )
    else:
        overrides["artifactctl_factory"] = lambda: store

    assembly = _memory_v2_assembly(tmp_path, **overrides)

    assert assembly.artifactctl is store
    first = assembly.close()
    second = assembly.close()

    assert first is second
    assert first.closed is True
    assert store.events == ["artifactctl.close"]


@pytest.mark.parametrize(
    "factory",
    [lambda: None, _unavailable_artifact_store],
    ids=["returns_none", "raises"],
)
def test_assembly_owns_no_artifact_store_the_factory_did_not_provide(
    tmp_path, factory
) -> None:
    assembly = _memory_v2_assembly(tmp_path, artifactctl_factory=factory)

    assert assembly.artifactctl is None
    assert assembly.close().closed is True


def test_gateway_only_assemblies_obtain_no_artifact_store(
    tmp_path, monkeypatch
) -> None:
    created: list[object] = []
    monkeypatch.setattr(
        "openminion.services.runtime.memory.create_default_artifactctl",
        lambda config=None: created.append(config),
    )
    disabled = OpenMinionConfig()
    disabled.runtime.memory_enabled = False
    smoke = OpenMinionConfig()
    smoke.runtime.memory_provider = "memory_v2_smoke"
    assemblies = [
        build_runtime_memory_assembly(
            config=config,
            agent_id="alpha",
            memory_root=tmp_path,
            logger=logging.getLogger("test.memory.artifact"),
        )
        for config in (disabled, smoke)
    ]
    assemblies.append(
        _memory_v2_assembly(
            tmp_path,
            resolve_runtime_memory_config_fn=lambda **kwargs: {
                "backend": {"provider": "none"}
            },
        )
    )

    for assembly in assemblies:
        assert assembly.artifactctl is None
        assert assembly.close().closed is True
    assert created == []


def test_disabled_assembly_keeps_gateway_without_runtime_owners() -> None:
    for gateway in (
        DisabledMemoryGatewayAdapter(agent_id="alpha"),
        EphemeralMemorySmokeProvider(agent_id="alpha"),
    ):
        assembly = RuntimeMemoryAssembly(gateway=gateway)

        assert assembly.gateway is gateway
        assert assembly.service is None
        assert assembly.memctl is None
        assert assembly.scheduler is None
        assert assembly.close().closed is True


def test_backend_none_builds_gateway_only_assembly(tmp_path) -> None:
    assembly = build_memory_v2_runtime_assembly(
        config=OpenMinionConfig(),
        agent_id="alpha",
        memory_root=tmp_path,
        logger=logging.getLogger("test.memory.none"),
        config_manager=None,
        home_root=None,
        data_root=None,
        session_context=None,
        retrieve_ctl=None,
        storage_path=None,
        resolve_runtime_memory_config_fn=lambda **kwargs: {
            "backend": {"provider": "none"}
        },
    )

    assert isinstance(assembly.gateway, DisabledMemoryGatewayAdapter)
    assert assembly.service is None
    assert assembly.memctl is None
    assert assembly.scheduler is None


def test_assembly_starts_and_closes_scheduler_before_service() -> None:
    events: list[str] = []
    service = _Service(events)
    adapter = _SnapshotVectorAdapter()
    scheduler = _BindingScheduler(events, adapter)
    assembly = active_runtime_memory_assembly(
        gateway=object(),
        service=service,  # type: ignore[arg-type]
        agent_id="alpha",
        vector_adapter=adapter,
        scheduler=scheduler,
    )

    assembly.start()
    first = assembly.close()
    second = assembly.close()

    assert scheduler.record_source is assembly.memctl
    assert events == [
        "scheduler.bind",
        "scheduler.start",
        "scheduler.stop",
        "service.close",
    ]
    assert first is second
    assert first.closed is True


def test_assembly_syncs_complete_snapshot_through_memctl(tmp_path) -> None:
    from openminion.modules.memory.service import MemoryService
    from openminion.modules.memory.storage.sqlite.store import SQLiteMemoryStore

    service = MemoryService(store=SQLiteMemoryStore(tmp_path / "memory.db"))
    service.write_record(
        scope="agent:alpha",
        record_type="fact",
        title="Canonical title",
        content="Canonical content",
    )
    adapter = _SnapshotVectorAdapter()
    scheduler = _BindingScheduler([], adapter)
    assembly = active_runtime_memory_assembly(
        gateway=object(),
        service=service,
        agent_id="alpha",
        vector_adapter=adapter,
        scheduler=scheduler,
    )

    assembly.start()

    assert len(adapter.snapshot["current"]) == 1
    assert adapter.snapshot["current"][0]["text"] == (
        "Canonical title\nCanonical content"
    )
    assembly.close()


def test_assembly_leaves_service_open_while_scheduler_is_live() -> None:
    events: list[str] = []
    service = _Service(events)
    scheduler = _Scheduler(events, live_after_stop=True)
    assembly = active_runtime_memory_assembly(
        gateway=object(),
        service=service,  # type: ignore[arg-type]
        agent_id="alpha",
        scheduler=scheduler,
        artifactctl=_ArtifactStore(events),
    )

    blocked = assembly.close()

    assert blocked.closed is False
    assert blocked.reason_code == "scheduler_still_running"
    assert events == ["scheduler.stop"]

    scheduler.live = False
    assert assembly.close().closed is True
    assert assembly.close().closed is True
    assert events == [
        "scheduler.stop",
        "scheduler.stop",
        "service.close",
        "artifactctl.close",
    ]


def test_artifact_store_close_error_keeps_recorded_memory_close() -> None:
    events: list[str] = []
    assembly = active_runtime_memory_assembly(
        gateway=object(),
        service=_Service(events),  # type: ignore[arg-type]
        agent_id="alpha",
        artifactctl=_FailingArtifactStore(events),
    )

    with pytest.raises(OSError, match="artifact index locked"):
        assembly.close()
    repeated = assembly.close()

    assert repeated.closed is True
    assert repeated.reason_code == "closed"
    assert events == ["service.close", "artifactctl.close"]
