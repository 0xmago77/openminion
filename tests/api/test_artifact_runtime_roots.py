"""SDK artifact reads and writes stay inside each runtime's explicit roots."""

import hashlib
from pathlib import Path

import pytest

from openminion import Agent, APIRuntime
from openminion.base.config import OpenMinionConfig, save_config
from openminion.modules.artifact.control import ArtifactCtl
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


def _echo_runtime(root: Path) -> APIRuntime:
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider="echo")
    config.runtime.process_mode = "single-process"
    config.runtime.daemon_auto_start = False
    config.storage.path = str(root / ".openminion" / "state.db")
    config_path = root / "agents.json"
    save_config(config, str(config_path))
    return APIRuntime.from_config_path(
        str(config_path), home_root=root, data_root=root / ".openminion"
    )


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
