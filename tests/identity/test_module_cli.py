from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner
import yaml

from openminion.modules.identity.cli import app
from openminion.modules.identity.storage.store import SQLiteIdentityStore


def _profile_payload(mission: str) -> dict:
    return {
        "agent_id": "ops-agent",
        "display_name": "Operations",
        "profile_revision": 1,
        "role": {"mission": mission},
        "personality": {"tone": "Precise"},
        "risk": {"risk_level": "medium"},
        "tool_posture": {"tool_use": "restricted"},
    }


def test_identityctl_upsert_uses_yaml_loader_and_generates_sidecars(
    tmp_path: Path,
) -> None:
    identity_root = tmp_path / "identity"
    profile_path = identity_root / "ops-agent" / "profile.yaml"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(
        yaml.safe_dump(_profile_payload("Canonical mission."), sort_keys=False),
        encoding="utf-8",
    )
    db_path = identity_root / "identity.db"
    config_path = tmp_path / "identityctl.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "storage": {"backend": "sqlite", "sqlite_path": str(db_path)},
                "profiles": {
                    "directory": str(identity_root),
                    "bundle_root": str(identity_root),
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        ["upsert", "--file", str(profile_path), "--config", str(config_path)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["agent_id"] == "ops-agent"
    store = SQLiteIdentityStore(sqlite_path=str(db_path))
    stored = store.get_profile("ops-agent")
    assert stored is not None
    assert stored.profile.meta["source"] == "yaml"
    assert stored.profile.meta["source_path"] == str(profile_path.resolve())
    assert (profile_path.parent / "AGENT.md").is_file()
    assert (profile_path.parent / "SOUL.md").is_file()
    assert (profile_path.parent / "README.md").is_file()


def test_identityctl_upsert_rejects_invalid_yaml_without_mutating_store(
    tmp_path: Path,
) -> None:
    identity_root = tmp_path / "identity"
    profile_path = identity_root / "ops-agent" / "profile.yaml"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(
        yaml.safe_dump(_profile_payload("Original mission."), sort_keys=False),
        encoding="utf-8",
    )
    db_path = identity_root / "identity.db"
    config_path = tmp_path / "identityctl.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "storage": {"backend": "sqlite", "sqlite_path": str(db_path)},
                "profiles": {"directory": str(identity_root)},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    first = runner.invoke(
        app,
        ["upsert", "--file", str(profile_path), "--config", str(config_path)],
    )
    assert first.exit_code == 0, first.output
    profile_path.write_text("agent_id: ops-agent\nrole: {}\n", encoding="utf-8")

    rejected = runner.invoke(
        app,
        ["upsert", "--file", str(profile_path), "--config", str(config_path)],
    )

    assert rejected.exit_code == 1
    store = SQLiteIdentityStore(sqlite_path=str(db_path))
    stored = store.get_profile("ops-agent")
    assert stored is not None
    assert stored.profile.role.mission == "Original mission."


def test_identityctl_upsert_rejects_profile_collection_without_mutating_store(
    tmp_path: Path,
) -> None:
    identity_root = tmp_path / "identity"
    identity_root.mkdir()
    db_path = identity_root / "identity.db"
    config_path = tmp_path / "identityctl.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "storage": {"backend": "sqlite", "sqlite_path": str(db_path)},
                "profiles": {"directory": str(identity_root)},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    collection = tmp_path / "profiles.yaml"
    collection.write_text(
        yaml.safe_dump(
            {
                "profiles": {
                    "alpha": _profile_payload("Alpha mission."),
                    "beta": {
                        **_profile_payload("Beta mission."),
                        "agent_id": "beta",
                    },
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    rejected = CliRunner().invoke(
        app,
        ["upsert", "--file", str(collection), "--config", str(config_path)],
    )

    assert rejected.exit_code == 1
    store = SQLiteIdentityStore(sqlite_path=str(db_path))
    assert store.list_profiles() == []
