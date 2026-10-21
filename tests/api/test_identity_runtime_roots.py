"""SDK identity reads and writes stay inside each runtime's explicit roots."""

import hashlib
from pathlib import Path

import pytest

from openminion import Agent, APIRuntime
from openminion.base.config import OpenMinionConfig, save_config
from openminion.modules.identity.models import (
    AgentProfile,
    PersonalitySpec,
    RiskSpec,
    RoleSpec,
    ToolPostureSpec,
)
from openminion.modules.identity.storage.repository import (
    create_sqlite_identity_repository,
)
from openminion.modules.llm.providers.echo.adapter import EchoProvider
from tests._csc_fixtures import _csc_install_default_agent

_AGENT_ID = "openminion"
_OVERRIDE_ENV_KEYS = (
    "OPENMINION_HOME",
    "OPENMINION_DATA_ROOT",
    "OPENMINION_GENERATED_ROOT",
    "OPENMINION_IDENTITY_DB",
    "OPENMINION_IDENTITY_ROOT",
    "OPENMINION_CONFIG_PATH",
)


def _identity_db(root: Path) -> Path:
    return root / ".openminion" / "identity" / "identity.db"


def _seed_profile(db_path: Path, mission: str) -> None:
    repo = create_sqlite_identity_repository(sqlite_path=db_path)
    try:
        repo.upsert_profile(
            AgentProfile(
                agent_id=_AGENT_ID,
                display_name=_AGENT_ID,
                profile_revision=1,
                role=RoleSpec(mission=mission),
                personality=PersonalitySpec(tone="professional", verbosity="normal"),
                risk=RiskSpec(risk_level="medium", confirm_before=[]),
                tool_posture=ToolPostureSpec(tool_use="allowed"),
                meta={},
            )
        )
    finally:
        repo.close()


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
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return home


def test_sdk_identity_reads_and_writes_stay_in_runtime_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unrelated_home: Path,
) -> None:
    home_db = _identity_db(unrelated_home)
    _seed_profile(home_db, "HOME_PROFILE_MARKER")
    root_a = tmp_path / "root-a"
    root_b = tmp_path / "root-b"
    _seed_profile(_identity_db(root_a), "ROOT_A_PROFILE_MARKER")
    root_b.mkdir()
    home_before = _snapshot(unrelated_home)

    prompts: list[str] = []
    complete = EchoProvider.complete

    def record_prompt(self, request, config):
        prompts.append("\n".join(str(message.content) for message in request.messages))
        return complete(self, request, config)

    monkeypatch.setattr(EchoProvider, "complete", record_prompt)

    rendered: dict[str, str] = {}
    runtime_a = _echo_runtime(root_a)
    runtime_b = _echo_runtime(root_b)
    try:
        for name, runtime in (("a", runtime_a), ("b", runtime_b)):
            prompts.clear()
            with Agent(runtime=runtime, session_id=f"identity-{name}") as agent:
                assert agent.run("hello").run_state == "completed"
            assert prompts
            rendered[name] = "\n".join(prompts)
    finally:
        runtime_a.close()
        runtime_b.close()

    assert "ROOT_A_PROFILE_MARKER" in rendered["a"]
    assert "HOME_PROFILE_MARKER" not in rendered["a"]
    assert "ROOT_A_PROFILE_MARKER" not in rendered["b"]
    assert "HOME_PROFILE_MARKER" not in rendered["b"]
    assert _snapshot(unrelated_home) == home_before
    assert sorted(tmp_path.rglob("identity.db")) == sorted(
        [home_db, _identity_db(root_a), _identity_db(root_b)]
    )
