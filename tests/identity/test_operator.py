from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from threading import Event, Thread
import time

import pytest
import yaml

from openminion.modules.identity.runtime import operator as identity_operator
from openminion.modules.identity.models import AgentProfile
from openminion.modules.identity.runtime.operator import (
    IdentityOperatorError,
    apply_identity_candidate,
    inspect_identity,
    reload_runtime_identity,
    runtime_identity_snapshot,
    validate_identity_candidate,
)
from openminion.modules.identity.runtime.service import IdentityCtl
from openminion.modules.identity.storage.store import SQLiteIdentityStore


def _profile_payload(
    agent_id: str = "ops-agent", mission: str = "Keep systems safe."
) -> dict:
    return {
        "agent_id": agent_id,
        "display_name": "Operations Agent",
        "profile_revision": 1,
        "role": {
            "mission": mission,
            "responsibilities": ["Inspect changes", "Report evidence", "Protect users"],
            "hard_constraints": [
                "Do not invent facts",
                "Confirm destructive work",
                "Preserve data",
            ],
            "domain": ["operations"],
            "escalation_rules": [],
        },
        "personality": {
            "tone": "Precise",
            "verbosity": "normal",
            "formatting": [],
            "interaction_style": [],
        },
        "risk": {
            "risk_level": "medium",
            "confirm_before": ["destructive changes"],
            "auto_proceed_rules": [],
        },
        "tool_posture": {
            "tool_use": "restricted",
            "blocked_patterns": [],
            "allowed_tools": [],
        },
    }


def _write_profile(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _ctl(tmp_path: Path) -> IdentityCtl:
    return IdentityCtl(
        store=SQLiteIdentityStore(sqlite_path=str(tmp_path / "identity.db"))
    )


def test_validate_candidate_is_read_only_and_returns_render(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())

    result = validate_identity_candidate(ctl, candidate_path=candidate)

    assert result["ok"] is True
    assert result["render"]["text"]
    assert result["render"]["budget"]["max_tokens"] == 180
    assert isinstance(result["render"]["warnings"], list)
    assert ctl.list_profiles() == []


def test_runtime_snapshot_keeps_render_budget_and_warnings(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    profile = AgentProfile.model_validate(_profile_payload())
    ctl.upsert_profile(profile)

    result = runtime_identity_snapshot(
        ctl,
        agent_id="ops-agent",
        purpose="act",
        max_tokens=20,
    )

    assert result is not None
    assert result["budget"]["max_tokens"] == 20
    assert result["warnings"] == [
        "snippet exceeds budget; truncation applied",
        "snippet still over budget after truncation",
    ]


def test_runtime_snapshot_includes_recorded_source_path(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    source = tmp_path / "identity" / "ops-agent" / "profile.yaml"
    profile = AgentProfile.model_validate(_profile_payload()).model_copy(
        update={"meta": {"source": "yaml", "source_path": str(source)}}
    )
    ctl.upsert_profile(profile)

    result = runtime_identity_snapshot(
        ctl,
        agent_id="ops-agent",
        purpose="act",
        max_tokens=180,
    )

    assert result is not None
    assert result["source_path"] == str(source)


def test_apply_writes_canonical_yaml_store_and_sidecars(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(
        candidate, _profile_payload(mission="Apply this identity precisely.")
    )

    result = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )

    profile_dir = identity_root / "ops-agent"
    assert result["source"] == "yaml"
    assert result["generated_sidecars"]["status"] == "clean"
    assert (profile_dir / "profile.yaml").is_file()
    assert (profile_dir / "AGENT.md").is_file()
    assert (profile_dir / "SOUL.md").is_file()
    assert (profile_dir / "README.md").is_file()
    assert (profile_dir / ".identity-lock.json").is_file()
    assert ctl.get_profile("ops-agent").role.mission == "Apply this identity precisely."


def test_stale_apply_preserves_yaml_and_store(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload(mission="Initial mission."))
    first = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    source = identity_root / "ops-agent" / "profile.yaml"
    original_yaml = source.read_text(encoding="utf-8")

    _write_profile(candidate, _profile_payload(mission="Stale replacement."))
    with pytest.raises(IdentityOperatorError, match="changed since") as exc_info:
        apply_identity_candidate(
            ctl,
            identity_root=identity_root,
            candidate_path=candidate,
            expected_profile_version="wrong-version",
            expected_source_sha256=first["source_sha256"],
        )

    assert exc_info.value.code == "stale_profile_version"
    assert source.read_text(encoding="utf-8") == original_yaml
    assert ctl.get_profile("ops-agent").role.mission == "Initial mission."
    assert first["profile_version"]


@pytest.mark.parametrize(
    ("payload_update", "code"),
    [
        ({"agent_id": "../escape"}, "unsafe_agent_id"),
        ({"inherits": "base-agent"}, "inherited_candidate"),
        (
            {"personality": {"tone": "Precise", "verbosity": "verbose"}},
            "invalid_candidate",
        ),
    ],
)
def test_invalid_candidate_does_not_mutate(
    tmp_path: Path,
    payload_update: dict,
    code: str,
) -> None:
    ctl = _ctl(tmp_path)
    candidate = tmp_path / "candidate.yaml"
    payload = _profile_payload()
    payload.update(payload_update)
    _write_profile(candidate, payload)

    with pytest.raises(IdentityOperatorError) as exc_info:
        apply_identity_candidate(
            ctl,
            identity_root=tmp_path / "identity",
            candidate_path=candidate,
            expected_profile_version="missing",
            expected_source_sha256="missing",
        )

    assert exc_info.value.code == code
    assert ctl.list_profiles() == []
    assert not (tmp_path / "identity").exists()


def test_inspect_distinguishes_authored_and_effective_state(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )

    inspected = inspect_identity(
        ctl,
        identity_root=identity_root,
        agent_id="ops-agent",
    )

    assert inspected["authored_yaml"]
    assert inspected["effective_profile"]["role"]["mission"] == "Keep systems safe."
    assert inspected["profile_version"] == applied["profile_version"]
    assert inspected["editable"] is True
    assert inspected["source_sha256"]
    assert inspected["verification"]["ok"] is True


def test_external_yaml_edit_trips_source_guard_without_overwrite(
    tmp_path: Path,
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload(mission="Initial mission."))
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    source = identity_root / "ops-agent" / "profile.yaml"
    _write_profile(source, _profile_payload(mission="External edit."))
    external_yaml = source.read_text(encoding="utf-8")
    _write_profile(candidate, _profile_payload(mission="Desktop edit."))

    with pytest.raises(IdentityOperatorError) as exc_info:
        apply_identity_candidate(
            ctl,
            identity_root=identity_root,
            candidate_path=candidate,
            expected_profile_version=applied["profile_version"],
            expected_source_sha256=applied["source_sha256"],
        )

    assert exc_info.value.code == "stale_source_sha256"
    assert source.read_text(encoding="utf-8") == external_yaml
    assert ctl.get_profile("ops-agent").role.mission == "Initial mission."
    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")
    assert inspected["verification"]["source_status"] == "drifted"
    assert inspected["verification"]["ok"] is False


def test_inspect_verifies_external_yaml_without_generated_sidecars(
    tmp_path: Path,
) -> None:
    ctl = _ctl(tmp_path)
    external = tmp_path / "external.yaml"
    _write_profile(external, _profile_payload())
    ctl.load_profiles_from_path(external)

    inspected = inspect_identity(
        ctl,
        identity_root=tmp_path / "identity",
        agent_id="ops-agent",
    )

    assert inspected["editable"] is False
    assert inspected["authored_yaml"] is None
    assert inspected["verification"]["source_status"] == "clean"
    assert inspected["verification"]["ok"] is True
    assert inspected["generated_sidecars"]["status"] == "not_applicable"


def test_inspect_explains_source_agent_id_mismatch(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    _write_profile(
        identity_root / "ops-agent" / "profile.yaml",
        _profile_payload(agent_id="other-agent"),
    )

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    issue = inspected["verification"]["issues"][0]
    assert issue == {
        "message": (
            "profile.yaml agent_id 'other-agent' does not match directory agent_id 'ops-agent'"
        ),
        "expected_agent_id": "ops-agent",
        "actual_agent_id": "other-agent",
    }


def test_missing_store_row_does_not_overwrite_existing_source(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    source = identity_root / "ops-agent" / "profile.yaml"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(source, _profile_payload(mission="Orphan source."))
    original_yaml = source.read_text(encoding="utf-8")
    _write_profile(candidate, _profile_payload(mission="Replacement."))

    with pytest.raises(IdentityOperatorError) as exc_info:
        apply_identity_candidate(
            ctl,
            identity_root=identity_root,
            candidate_path=candidate,
            expected_profile_version="missing",
            expected_source_sha256="missing",
        )

    assert exc_info.value.code == "stale_source_sha256"
    assert source.read_text(encoding="utf-8") == original_yaml
    assert ctl.get_profile("ops-agent") is None


def test_sync_failure_restores_source_store_and_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload(mission="Initial mission."))
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    profile_dir = identity_root / "ops-agent"
    unrelated = _profile_payload(agent_id="unrelated-agent", mission="Unrelated.")
    ctl.upsert_profile(AgentProfile.model_validate(unrelated))
    original_target_row = ctl.store.get_profile("ops-agent")
    original_unrelated_row = ctl.store.get_profile("unrelated-agent")
    before = {
        path.name: path.read_bytes() for path in profile_dir.iterdir() if path.is_file()
    }
    original_load = ctl.load_profiles_from_path

    def fail_after_sync(path: Path, *, identity_root: Path | None = None) -> list[str]:
        original_load(path, identity_root=identity_root)
        raise RuntimeError("forced synchronization failure")

    monkeypatch.setattr(ctl, "load_profiles_from_path", fail_after_sync)
    _write_profile(candidate, _profile_payload(mission="Rejected mission."))

    with pytest.raises(IdentityOperatorError) as exc_info:
        apply_identity_candidate(
            ctl,
            identity_root=identity_root,
            candidate_path=candidate,
            expected_profile_version=applied["profile_version"],
            expected_source_sha256=applied["source_sha256"],
        )

    assert exc_info.value.code == "synchronization_failed"
    assert ctl.get_profile("ops-agent").role.mission == "Initial mission."
    assert ctl.store.get_profile("ops-agent") == original_target_row
    assert ctl.store.get_profile("unrelated-agent") == original_unrelated_row
    assert {
        path.name: path.read_bytes() for path in profile_dir.iterdir() if path.is_file()
    } == before


def test_empty_sync_result_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload(mission="Initial mission."))
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    source = identity_root / "ops-agent" / "profile.yaml"
    original_yaml = source.read_text(encoding="utf-8")
    original_row = ctl.store.get_profile("ops-agent")
    monkeypatch.setattr(
        ctl,
        "load_profiles_from_path",
        lambda _path, *, identity_root=None: [],
    )
    _write_profile(candidate, _profile_payload(mission="Rejected mission."))

    with pytest.raises(IdentityOperatorError, match="synchronization failed"):
        apply_identity_candidate(
            ctl,
            identity_root=identity_root,
            candidate_path=candidate,
            expected_profile_version=applied["profile_version"],
            expected_source_sha256=applied["source_sha256"],
        )

    assert source.read_text(encoding="utf-8") == original_yaml
    assert ctl.store.get_profile("ops-agent") == original_row


def test_concurrent_apply_rechecks_state_under_profile_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity_root = tmp_path / "identity"
    initial = tmp_path / "initial.yaml"
    first_candidate = tmp_path / "first.yaml"
    second_candidate = tmp_path / "second.yaml"
    _write_profile(initial, _profile_payload(mission="Initial mission."))
    applied = apply_identity_candidate(
        _ctl(tmp_path),
        identity_root=identity_root,
        candidate_path=initial,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    _write_profile(first_candidate, _profile_payload(mission="First writer."))
    _write_profile(second_candidate, _profile_payload(mission="Second writer."))
    entered = Event()
    release = Event()
    original_write = identity_operator._write_and_sync_profile

    def delayed_write(ctl: IdentityCtl, *, profile: AgentProfile, target: Path) -> None:
        if profile.role.mission == "First writer.":
            entered.set()
            assert release.wait(timeout=5)
        original_write(ctl, profile=profile, target=target)

    monkeypatch.setattr(identity_operator, "_write_and_sync_profile", delayed_write)
    results: list[object] = []

    def apply(path: Path) -> None:
        try:
            results.append(
                apply_identity_candidate(
                    _ctl(tmp_path),
                    identity_root=identity_root,
                    candidate_path=path,
                    expected_profile_version=applied["profile_version"],
                    expected_source_sha256=applied["source_sha256"],
                )
            )
        except Exception as exc:  # test captures the losing writer
            results.append(exc)

    first = Thread(target=apply, args=(first_candidate,))
    second = Thread(target=apply, args=(second_candidate,))
    first.start()
    assert entered.wait(timeout=5)
    second.start()
    time.sleep(0.05)
    assert second.is_alive()
    release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    errors = [item for item in results if isinstance(item, IdentityOperatorError)]
    assert len(errors) == 1
    assert errors[0].code in {"stale_profile_version", "stale_source_sha256"}
    assert _ctl(tmp_path).get_profile("ops-agent").role.mission == "First writer."


@pytest.mark.parametrize("generated_name", ["AGENT.md", ".identity-lock.json"])
def test_apply_replaces_generated_symlinks_without_touching_external_files(
    tmp_path: Path, generated_name: str
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    generated_path = identity_root / "ops-agent" / generated_name
    external = tmp_path / "external.txt"
    external.write_text("do not overwrite", encoding="utf-8")
    generated_path.unlink()
    generated_path.symlink_to(external)
    _write_profile(candidate, _profile_payload(mission="Updated mission."))

    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version=applied["profile_version"],
        expected_source_sha256=applied["source_sha256"],
    )

    assert external.read_text(encoding="utf-8") == "do not overwrite"
    assert generated_path.is_file()
    assert not generated_path.is_symlink()


def test_apply_rejects_symlinked_profile_lock(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    lock_path = identity_root / "ops-agent" / ".identity-apply.lock"
    lock_path.unlink()
    external = tmp_path / "external-lock"
    external.write_bytes(b"external")
    lock_path.symlink_to(external)
    _write_profile(candidate, _profile_payload(mission="Rejected mission."))

    with pytest.raises(IdentityOperatorError) as exc_info:
        apply_identity_candidate(
            ctl,
            identity_root=identity_root,
            candidate_path=candidate,
            expected_profile_version=applied["profile_version"],
            expected_source_sha256=applied["source_sha256"],
        )

    assert exc_info.value.code == "unsafe_lock_path"
    assert external.read_bytes() == b"external"


def test_windows_profile_lock_uses_the_same_fixed_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    positions: list[tuple[int, int]] = []

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(descriptor: int, mode: int, length: int) -> None:
            with os.fdopen(os.dup(descriptor), "rb") as duplicate:
                positions.append((mode, duplicate.tell()))
            assert length == 1

    target = tmp_path / "profile.yaml"
    monkeypatch.setitem(sys.modules, "msvcrt", FakeMsvcrt)
    monkeypatch.setattr(identity_operator.os, "name", "nt")

    with identity_operator._profile_apply_lock(target):
        pass

    assert positions == [(FakeMsvcrt.LK_LOCK, 0), (FakeMsvcrt.LK_UNLCK, 0)]


def test_inspect_rejects_canonical_source_symlink_escape(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    source = identity_root / "ops-agent" / "profile.yaml"
    external = tmp_path / "external.yaml"
    _write_profile(external, _profile_payload(mission="External secret."))
    source.unlink()
    source.symlink_to(external)

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["authored_yaml"] is None
    assert inspected["editable"] is False
    assert inspected["verification"]["source_status"] == "missing"


def test_reload_runtime_identity_uses_recorded_external_yaml(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    external_root = tmp_path / "external"
    external_root.mkdir()
    source = external_root / "profile.yaml"
    _write_profile(source, _profile_payload(mission="Original external mission."))
    ctl.load_profiles_from_path(source, identity_root=identity_root)
    _write_profile(source, _profile_payload(mission="Reloaded external mission."))

    reload_runtime_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    profile = ctl.get_profile("ops-agent")
    assert profile is not None
    assert profile.role.mission == "Reloaded external mission."
    assert not (external_root / "AGENT.md").exists()


@pytest.mark.parametrize(
    "relative_path", ["../external.md", "/tmp/external.md", "linked.md"]
)
def test_inspect_rejects_unsafe_lockfile_paths(
    tmp_path: Path, relative_path: str
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    profile_root = identity_root / "ops-agent"
    external = tmp_path / "external.md"
    external.write_text("external", encoding="utf-8")
    if relative_path == "linked.md":
        (profile_root / relative_path).symlink_to(external)
    lock_path = profile_root / ".identity-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["files"] = [
        {
            "relative_path": relative_path,
            "sha256": identity_operator.sha256(external.read_bytes()).hexdigest(),
            "size_bytes": external.stat().st_size,
        }
    ]
    lock["generated_from_profile_version"] = applied["profile_version"]
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["generated_sidecars"]["status"] == "drifted"
    assert relative_path in inspected["generated_sidecars"]["drifted_files"]


def test_inspect_rejects_lockfile_missing_required_generated_files(
    tmp_path: Path,
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    applied = apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    profile_root = identity_root / "ops-agent"
    lock_path = profile_root / ".identity-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["files"] = []
    lock["generated_from_profile_version"] = applied["profile_version"]
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    for name in ("AGENT.md", "SOUL.md", "README.md"):
        (profile_root / name).unlink()

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["generated_sidecars"]["status"] == "drifted"
    assert inspected["generated_sidecars"]["drifted_files"] == [
        ".identity-lock.json",
        "AGENT.md",
        "README.md",
        "SOUL.md",
    ]
    assert inspected["verification"]["ok"] is False


def test_inspect_rejects_generated_file_rehashed_in_lockfile(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    profile_root = identity_root / "ops-agent"
    generated = profile_root / "AGENT.md"
    generated.write_text("# Rewritten generated identity\n", encoding="utf-8")
    lock_path = profile_root / ".identity-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    for item in lock["files"]:
        if item["relative_path"] == "AGENT.md":
            item["sha256"] = identity_operator.sha256(
                generated.read_bytes()
            ).hexdigest()
            item["size_bytes"] = generated.stat().st_size
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["generated_sidecars"]["status"] == "drifted"
    assert "AGENT.md" in inspected["generated_sidecars"]["drifted_files"]
    assert inspected["verification"]["ok"] is False


def test_inspect_rejects_extra_rehashed_generated_manifest_entry(
    tmp_path: Path,
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    profile_root = identity_root / "ops-agent"
    extra = profile_root / "EXTRA.md"
    extra.write_text("# Extra\n", encoding="utf-8")
    lock_path = profile_root / ".identity-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["files"].append(
        {
            "relative_path": "EXTRA.md",
            "sha256": identity_operator.sha256(extra.read_bytes()).hexdigest(),
            "size_bytes": extra.stat().st_size,
        }
    )
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["generated_sidecars"]["status"] == "drifted"
    assert "EXTRA.md" in inspected["generated_sidecars"]["drifted_files"]
    assert inspected["verification"]["ok"] is False


@pytest.mark.parametrize(
    ("field", "expected_drift"),
    [
        ("size_bytes", "AGENT.md"),
        ("tree_sha256", ".identity-lock.json"),
    ],
)
def test_inspect_rejects_invalid_generated_manifest_integrity(
    tmp_path: Path, field: str, expected_drift: str
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    lock_path = identity_root / "ops-agent" / ".identity-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if field == "size_bytes":
        lock["files"][0]["size_bytes"] = 999
    else:
        lock["tree_sha256"] = "0" * 64
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["generated_sidecars"]["status"] == "drifted"
    assert expected_drift in inspected["generated_sidecars"]["drifted_files"]
    assert inspected["verification"]["ok"] is False


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {
            "generated_from_profile_version": "version",
            "files": [
                {"relative_path": "AGENT.md", "sha256": "a", "size_bytes": 1},
                {"relative_path": "AGENT.md", "sha256": "a", "size_bytes": 1},
            ],
        },
        {
            "generated_from_profile_version": "version",
            "files": [
                {
                    "relative_path": "AGENT.md",
                    "sha256": "a",
                    "size_bytes": "1",
                }
            ],
        },
    ],
)
def test_inspect_marks_malformed_generated_lockfile_invalid(
    tmp_path: Path, payload: object
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    candidate = tmp_path / "candidate.yaml"
    _write_profile(candidate, _profile_payload())
    apply_identity_candidate(
        ctl,
        identity_root=identity_root,
        candidate_path=candidate,
        expected_profile_version="missing",
        expected_source_sha256="missing",
    )
    lock_path = identity_root / "ops-agent" / ".identity-lock.json"
    lock_path.write_text(json.dumps(payload), encoding="utf-8")

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="ops-agent")

    assert inspected["generated_sidecars"]["status"] == "invalid"
    assert inspected["verification"]["ok"] is False


def test_inspect_marks_generated_sidecars_not_applicable_for_default_profile(
    tmp_path: Path,
) -> None:
    ctl = _ctl(tmp_path)
    profile = AgentProfile.model_validate(_profile_payload()).model_copy(
        update={"meta": {"source": "default"}}
    )
    ctl.upsert_profile(profile)

    inspected = inspect_identity(
        ctl,
        identity_root=tmp_path / "identity",
        agent_id="ops-agent",
    )

    assert inspected["generated_sidecars"]["status"] == "not_applicable"


def test_inspect_rejects_bundle_profile_without_recorded_root(tmp_path: Path) -> None:
    ctl = _ctl(tmp_path)
    profile = AgentProfile.model_validate(_profile_payload()).model_copy(
        update={
            "meta": {
                "source": "bundle",
                "bundle_fingerprint": "stored-fingerprint",
            }
        }
    )
    ctl.upsert_profile(profile)

    inspected = inspect_identity(
        ctl,
        identity_root=tmp_path / "identity",
        agent_id="ops-agent",
    )

    assert inspected["verification"]["ok"] is False
    assert inspected["verification"]["source_status"] == "invalid"
    assert inspected["verification"]["issues"] == [
        {"message": "recorded bundle root is missing"}
    ]
    assert inspected["verification"]["sidecar_status"] == "not_applicable"


def test_inspect_verifies_inherited_yaml_without_making_it_editable(
    tmp_path: Path,
) -> None:
    ctl = _ctl(tmp_path)
    identity_root = tmp_path / "identity"
    _write_profile(identity_root / "base" / "profile.yaml", _profile_payload("base"))
    child = {
        "agent_id": "child",
        "inherits": "base",
        "role": {"mission": "Child mission."},
    }
    _write_profile(identity_root / "child" / "profile.yaml", child)
    ctl.load_profiles_from_path(identity_root)

    inspected = inspect_identity(ctl, identity_root=identity_root, agent_id="child")

    assert inspected["editable"] is False
    assert inspected["verification"]["source_status"] == "clean"
    assert inspected["verification"]["ok"] is True

    _write_profile(
        identity_root / "base" / "profile.yaml",
        _profile_payload("base", mission="Changed parent mission."),
    )
    drifted = inspect_identity(ctl, identity_root=identity_root, agent_id="child")

    assert drifted["verification"]["source_status"] == "drifted"
    assert drifted["verification"]["source_profile_version"] is None
    assert drifted["verification"]["ok"] is False
    assert any(
        "inherited source is not clean" in issue["message"]
        for issue in drifted["verification"]["issues"]
    )
