from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from openminion.base.config.mcp import MCPServerConfig
from openminion.base.config.runtime import RuntimeConfig
from openminion.modules.tool.bootstrap import build_runtime_bootstrap
from openminion.modules.tool.base import ToolExecutionContext
from openminion.modules.tool.contracts import ProviderToolCall
from openminion.modules.tool.exposure import (
    get_model_exposure_specs,
    get_visible_tool_specs_and_dispatch_map,
)
from openminion.tools.mcp.interfaces import (
    MCPCapabilityApplyResult,
    MCPCapabilityChangeListener,
)
from openminion.tools.mcp.manager import MCPFleetManager
from openminion.tools.mcp.schemas import (
    MCPListedResource,
    MCPListedResourceTemplate,
    MCPListedTool,
)


FIXTURE_SERVER_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "mock_mcp_server.py"
)


class _Listener(MCPCapabilityChangeListener):
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def capability_changed(
        self,
        *,
        server_name: str,
        snapshots: dict[str, tuple[Any, ...]],
        added: dict[str, tuple[str, ...]],
        removed: dict[str, tuple[str, ...]],
    ) -> MCPCapabilityApplyResult:
        with self._lock:
            for primitive in snapshots:
                self.events.append(
                    {
                        "server_name": server_name,
                        "primitive": primitive,
                        "added": tuple(added.get(primitive, ())),
                        "removed": tuple(removed.get(primitive, ())),
                    }
                )
        return MCPCapabilityApplyResult(status="applied")


def _runtime_config() -> RuntimeConfig:
    return RuntimeConfig(
        mcp_servers=[
            MCPServerConfig(
                name="Fixture",
                transport="stdio",
                trusted=True,
                command=[sys.executable, str(FIXTURE_SERVER_PATH)],
                request_timeout_seconds=5.0,
                startup_timeout_seconds=5.0,
            )
        ]
    )


def _wait_for(predicate, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("timed out waiting for capability-change event")


def test_list_changed_notifications_route_each_primitive_to_listener() -> None:
    listener = _Listener()
    manager = MCPFleetManager(
        servers=_runtime_config().mcp_servers,
        capability_change_listener=listener,
    )
    try:
        manager.discover_tools()
        manager.discover_prompts()
        manager.discover_resources()
        session = manager._sessions["fixture"]

        session._handle_server_notification(
            method="notifications/tools/list_changed",
            params={},
        )
        session._handle_server_notification(
            method="notifications/prompts/list_changed",
            params={},
        )
        session._handle_server_notification(
            method="notifications/resources/list_changed",
            params={},
        )

        def _saw_all() -> bool:
            primitives = {item["primitive"] for item in listener.events}
            return primitives >= {
                "tools",
                "prompts",
                "resources",
                "resource_templates",
            }

        _wait_for(_saw_all)
    finally:
        manager.close()


def test_emit_list_changed_refreshes_catalog_and_reports_added_tool() -> None:
    listener = _Listener()
    manager = MCPFleetManager(
        servers=_runtime_config().mcp_servers,
        capability_change_listener=listener,
    )
    try:
        discovered = manager.discover_tools()
        assert all(tool.remote_name != "dynamic-after-change" for tool in discovered)

        result = manager.call_tool(
            server_name="fixture",
            remote_name="emit-list-changed",
            arguments={},
        )
        assert result["ok"] is True

        def _dynamic_added() -> bool:
            return any(
                item["primitive"] == "tools" and "dynamic-after-change" in item["added"]
                for item in listener.events
            )

        _wait_for(_dynamic_added)
        events = manager.capability_change_events()
        assert any(
            item["primitive"] == "tools" and "dynamic-after-change" in item["added"]
            for item in events
        )
    finally:
        manager.close()


def test_list_changed_updates_live_registry_and_model_exposure() -> None:
    bootstrap = build_runtime_bootstrap(config=_runtime_config(), strict=True)
    try:
        registry = bootstrap.registry
        manager = bootstrap.mcp_manager
        assert manager is not None
        assert "mcp.fixture.dynamic_after_change" not in registry.list()

        result = manager.call_tool(
            server_name="fixture",
            remote_name="emit-list-changed",
            arguments={},
        )
        assert result["ok"] is True

        _wait_for(
            lambda: any(
                item["primitive"] == "tools"
                and item["apply_status"] == "applied"
                and "dynamic-after-change" in item["added"]
                for item in manager.capability_change_events()
            )
        )
        dynamic_name = "mcp.fixture.dynamic_after_change"
        assert dynamic_name in registry.list()
        assert dynamic_name in {
            spec.name for spec in get_model_exposure_specs(registry)
        }

        dynamic_result = registry.get(dynamic_name).handler({}, None)
        assert dynamic_result["data"]["structured_content"]["dynamic"] is True

        result = manager.call_tool(
            server_name="fixture",
            remote_name="emit-list-changed",
            arguments={},
        )
        assert result["ok"] is True
        _wait_for(lambda: dynamic_name not in registry.list())
        assert dynamic_name not in {
            spec.name for spec in get_model_exposure_specs(registry)
        }
    finally:
        manager = getattr(bootstrap, "mcp_manager", None)
        if manager is not None:
            manager.close()


def test_resource_and_template_catalogs_are_independent() -> None:
    manager = MCPFleetManager(servers=[])
    manager._update_catalog(  # noqa: SLF001
        primitive="resources",
        server_name="fixture",
        items=[
            MCPListedResource(
                server_name="fixture",
                resource_uri="file://fixture/readme.md",
                resource_name="README",
                description="",
                mime_type="text/markdown",
            )
        ],
    )
    manager._update_catalog(  # noqa: SLF001
        primitive="resource_templates",
        server_name="fixture",
        items=[
            MCPListedResourceTemplate(
                server_name="fixture",
                uri_template="file://fixture/{name}",
                template_name="document",
                description="",
                mime_type="text/plain",
                arguments_schema={},
            )
        ],
    )

    assert manager._catalog_for("resources", "fixture") == (  # noqa: SLF001
        "file://fixture/readme.md",
    )
    assert manager._catalog_for("resource_templates", "fixture") == (  # noqa: SLF001
        "file://fixture/{name}",
    )


def test_stale_fleet_refresh_cannot_replace_active_registry() -> None:
    bootstrap = build_runtime_bootstrap(config=_runtime_config(), strict=True)
    registry = bootstrap.registry
    manager = bootstrap.mcp_manager
    synchronizer = registry.mcp_synchronizer
    assert manager is not None
    assert synchronizer is not None
    before = set(registry.list())
    registry.mcp_manager = MCPFleetManager(servers=[])
    try:
        result = synchronizer.capability_changed(
            server_name="fixture",
            snapshots={"tools": ()},
            added={"tools": ()},
            removed={"tools": ()},
        )
        assert result.status == "stale"
        assert set(registry.list()) == before
    finally:
        registry.mcp_manager.close()
        registry.mcp_manager = manager
        manager.close()


def test_in_flight_mcp_handler_completes_during_registry_replacement() -> None:
    bootstrap = build_runtime_bootstrap(config=_runtime_config(), strict=True)
    registry = bootstrap.registry
    manager = bootstrap.mcp_manager
    synchronizer = registry.mcp_synchronizer
    assert manager is not None
    assert synchronizer is not None
    tool_name = "mcp.fixture.echo_text"
    tool = registry.get(tool_name)
    original_handler = tool.handler
    started = threading.Event()
    release = threading.Event()

    def _blocked_handler(arguments, context):
        started.set()
        release.wait(timeout=5)
        return original_handler(arguments, context)

    tool.handler = _blocked_handler

    def _execute():
        return registry.execute_calls(
            [ProviderToolCall(name=tool_name, arguments={"text": "still-running"})],
            context=ToolExecutionContext(
                channel="console",
                target="unit-test",
                session_id="mcp-in-flight",
            ),
        ).results[0]

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_execute)
            assert started.wait(timeout=5)
            applied = synchronizer.capability_changed(
                server_name="fixture",
                snapshots={"tools": ()},
                added={"tools": ()},
                removed={"tools": ("echo",)},
            )
            assert applied.status == "applied"
            assert tool_name not in registry.list()
            release.set()
            result = future.result(timeout=5)
        assert result.ok is True
        assert "still-running" in result.content
    finally:
        release.set()
        manager.close()


def test_collision_failure_leaves_live_registry_unchanged() -> None:
    bootstrap = build_runtime_bootstrap(config=_runtime_config(), strict=True)
    registry = bootstrap.registry
    manager = bootstrap.mcp_manager
    synchronizer = registry.mcp_synchronizer
    assert manager is not None
    assert synchronizer is not None
    before = set(registry.list())
    collision = tuple(
        MCPListedTool(
            server_name="fixture",
            remote_name=name,
            description="collision",
            input_schema={"type": "object", "properties": {}},
        )
        for name in ("same-name", "same_name")
    )
    try:
        result = synchronizer.capability_changed(
            server_name="fixture",
            snapshots={"tools": collision},
            added={"tools": ("same-name", "same_name")},
            removed={"tools": ()},
        )
        assert result.status == "failed"
        assert result.error
        assert set(registry.list()) == before
    finally:
        manager.close()


def test_duplicate_capability_refreshes_are_coalesced(monkeypatch) -> None:
    manager = MCPFleetManager(servers=_runtime_config().mcp_servers)
    started = threading.Event()
    release = threading.Event()
    calls: list[tuple[str, str]] = []

    def _refresh(*, server_name: str, primitive: str) -> None:
        calls.append((server_name, primitive))
        started.set()
        release.wait(timeout=5)

    monkeypatch.setattr(manager, "_refresh_capability_change", _refresh)
    try:
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        assert started.wait(timeout=5)
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        release.set()
        _wait_for(lambda: not manager._refresh_pending)  # noqa: SLF001

        assert calls == [("fixture", "tools"), ("fixture", "tools")]
    finally:
        release.set()
        manager.close()


def test_refresh_failure_releases_pending_slot(monkeypatch) -> None:
    manager = MCPFleetManager(servers=_runtime_config().mcp_servers)
    failed = threading.Event()
    recovered = threading.Event()

    def _fail(*, server_name: str, primitive: str) -> None:
        del server_name, primitive
        failed.set()
        raise RuntimeError("refresh failed")

    monkeypatch.setattr(manager, "_refresh_capability_change", _fail)
    try:
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        assert failed.wait(timeout=5)
        _wait_for(lambda: not manager._refresh_pending)  # noqa: SLF001

        def _recover(*, server_name: str, primitive: str) -> None:
            del server_name, primitive
            recovered.set()

        monkeypatch.setattr(manager, "_refresh_capability_change", _recover)
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        assert recovered.wait(timeout=5)
        _wait_for(lambda: not manager._refresh_pending)  # noqa: SLF001
    finally:
        manager.close()


def test_refresh_failure_replays_notification_received_in_flight(monkeypatch) -> None:
    manager = MCPFleetManager(servers=_runtime_config().mcp_servers)
    started = threading.Event()
    release = threading.Event()
    recovered = threading.Event()
    calls = 0

    def _refresh(*, server_name: str, primitive: str) -> None:
        nonlocal calls
        del server_name, primitive
        calls += 1
        if calls == 1:
            started.set()
            release.wait(timeout=5)
            raise RuntimeError("refresh failed")
        recovered.set()

    monkeypatch.setattr(manager, "_refresh_capability_change", _refresh)
    try:
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        assert started.wait(timeout=5)
        manager._on_capability_change(  # noqa: SLF001
            server_name="fixture", primitive="tools"
        )
        release.set()

        assert recovered.wait(timeout=5)
        _wait_for(lambda: not manager._refresh_pending)  # noqa: SLF001
        assert calls == 2
    finally:
        release.set()
        manager.close()


def test_live_refresh_publishes_matching_model_and_dispatch_snapshots() -> None:
    bootstrap = build_runtime_bootstrap(config=_runtime_config(), strict=True)
    registry = bootstrap.registry
    manager = bootstrap.mcp_manager
    assert manager is not None
    dynamic_name = "mcp.fixture.dynamic_after_change"
    mismatches: list[tuple[bool, bool]] = []
    stop = threading.Event()

    def _read_exposure() -> None:
        while not stop.is_set():
            specs, dispatch = get_visible_tool_specs_and_dispatch_map(registry)
            in_specs = dynamic_name in {spec.name for spec in specs}
            in_dispatch = dynamic_name in dispatch
            if in_specs != in_dispatch:
                mismatches.append((in_specs, in_dispatch))

    reader = threading.Thread(target=_read_exposure)
    reader.start()
    try:
        for _ in range(4):
            manager.call_tool(
                server_name="fixture",
                remote_name="emit-list-changed",
                arguments={},
            )
            _wait_for(lambda: (dynamic_name in registry.list()) != (_ % 2 == 1))
    finally:
        stop.set()
        reader.join(timeout=5)
        manager.close()

    assert mismatches == []
