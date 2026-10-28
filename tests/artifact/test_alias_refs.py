from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.artifact.errors import ArtifactCtlError
from openminion.modules.artifact.models import sha_to_ref
from openminion.modules.artifact.refs import (
    normalize_artifact_ref_targets,
    remove_owner_reference_edges,
    remove_reference_edges,
)

from .utils import artifact_ctl, run_cli_command, write_config_file


def test_alias_set_respects_overwrite_flag(tmp_path):
    with artifact_ctl(tmp_path) as ctl:
        ref_a = ctl.ingest_bytes(b"alpha", original_name="alpha.txt")
        ref_b = ctl.ingest_bytes(b"beta", original_name="beta.txt")

        ctl.alias_set("session:s1/latest", ref_a.sha256)
        with pytest.raises(ArtifactCtlError):
            ctl.alias_set("session:s1/latest", ref_b.sha256, overwrite=False)

        ctl.alias_set("session:s1/latest", ref_b.sha256)
        resolved = ctl.alias_resolve("session:s1/latest")
        assert resolved is not None
        assert resolved.sha256 == ref_b.sha256


def test_alias_and_reference_targets_must_be_active(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        active = ctl.ingest_bytes(b"active", original_name="active.txt")
        deleted = ctl.ingest_bytes(b"deleted", original_name="deleted.txt")
        ctl.ref_add("session", "s1", deleted.sha256)
        ctl.delete(deleted.sha256)

        for target in ("f" * 64, deleted.sha256):
            with pytest.raises(ArtifactCtlError) as alias_error:
                ctl.alias_set("new-alias", target)
            assert alias_error.value.code == "NOT_FOUND"

            with pytest.raises(ArtifactCtlError) as ref_error:
                ctl.ref_add("session", "s2", target)
            assert ref_error.value.code == "NOT_FOUND"

        ctl.alias_set("existing-alias", active.sha256)
        with pytest.raises(ArtifactCtlError) as existing_error:
            ctl.alias_set("existing-alias", deleted.sha256, overwrite=False)
        assert existing_error.value.code == "ALREADY_EXISTS"

        ctl.ref_remove("session", "s1", deleted.sha256)
        assert deleted.sha256 not in ctl.index.active_reference_shas()


def test_alias_expiry_filters_list_and_resolve(tmp_path):
    with artifact_ctl(tmp_path) as ctl:
        ref = ctl.ingest_bytes(b"payload", original_name="payload.bin")
        expires = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        ctl.alias_set("alias:expired", ref.sha256, expires_at=expires)
        assert ctl.alias_resolve("alias:expired") is None
        assert all(item["alias"] != "alias:expired" for item in ctl.alias_list())


@pytest.mark.parametrize("expires_at", ["not-a-date", "2026-10-28T12:00:00"])
def test_invalid_alias_expiry_fails_before_index_or_ref_lookup(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    expires_at: str,
) -> None:
    with artifact_ctl(tmp_path) as ctl:
        alias_lookup = Mock(wraps=ctl.index.alias_resolve)
        ref_lookup = Mock(wraps=ctl._resolve_active_sha)
        monkeypatch.setattr(ctl.index, "alias_resolve", alias_lookup)
        monkeypatch.setattr(ctl, "_resolve_active_sha", ref_lookup)

        with pytest.raises(ArtifactCtlError) as exc_info:
            ctl.alias_set("alias:invalid", "a" * 64, expires_at=expires_at)

        assert exc_info.value.code == "INVALID_ARGUMENT"
        alias_lookup.assert_not_called()
        ref_lookup.assert_not_called()


@pytest.mark.parametrize(
    ("expires_at", "expected"),
    [
        ("2030-10-28T12:00:00Z", "2030-10-28T12:00:00+00:00"),
        ("2030-10-28T12:00:00+14:00", "2030-10-27T22:00:00+00:00"),
        ("2030-10-28T12:00:00-07:00", "2030-10-28T19:00:00+00:00"),
    ],
)
def test_alias_expiry_is_stored_in_utc(
    tmp_path, expires_at: str, expected: str
) -> None:
    with artifact_ctl(tmp_path) as ctl:
        ref = ctl.ingest_bytes(b"payload", original_name="payload.txt")

        ctl.alias_set("alias:utc", ref.sha256, expires_at=expires_at)

        alias = next(item for item in ctl.alias_list() if item["alias"] == "alias:utc")
        assert alias["expires_at"] == expected


def test_expired_offset_alias_does_not_protect_artifact(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        ref = ctl.ingest_bytes(b"payload", original_name="payload.txt")
        ctl.alias_set(
            "alias:expired-offset",
            ref.sha256,
            expires_at="2000-01-01T12:00:00+14:00",
        )

        assert ctl.alias_resolve("alias:expired-offset") is None
        assert ref.sha256 not in ctl.index.active_alias_shas()


def test_reference_edge_idempotency(tmp_path):
    with artifact_ctl(tmp_path) as ctl:
        ref = ctl.ingest_bytes(b"keep", original_name="keep.txt")

        ctl.ref_add("session", "s1", ref.sha256)
        ctl.ref_add("session", "s1", ref.sha256)
        assert ref.sha256 in ctl.index.active_reference_shas()


@pytest.mark.parametrize("owner_id", ["", "   "])
def test_reference_add_rejects_blank_owner_before_ref_lookup(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    owner_id: str,
) -> None:
    with artifact_ctl(tmp_path) as ctl:
        ref_lookup = Mock(wraps=ctl._resolve_active_sha)
        monkeypatch.setattr(ctl, "_resolve_active_sha", ref_lookup)

        with pytest.raises(ArtifactCtlError) as exc_info:
            ctl.ref_add("session", owner_id, "a" * 64)

        assert exc_info.value.code == "INVALID_ARGUMENT"
        ref_lookup.assert_not_called()


def test_reference_remove_cleans_seeded_blank_owner_edges(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        ref = ctl.ingest_bytes(b"legacy", original_name="legacy.txt")
        ctl.index.add_reference("session", "", ref.sha256)

        ctl.ref_remove("session", "", ref.sha256)

        assert ref.sha256 not in ctl.index.active_reference_shas()
        ctl.index.add_reference("session", "", ref.sha256)
        ctl.ref_remove_owner("session", "")
        assert ref.sha256 not in ctl.index.active_reference_shas()


def test_remove_owner_reference_edges_is_exact_and_idempotent(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        shared = ctl.ingest_bytes(b"shared", original_name="shared.txt")
        other = ctl.ingest_bytes(b"other", original_name="other.txt")
        ctl.ref_add("session", "session-a", shared.sha256)
        ctl.ref_add("session", "session-a", other.sha256)
        ctl.ref_add("session", "session-b", shared.sha256)

        remove_owner_reference_edges(
            artifactctl=ctl,
            owner_type="session",
            owner_id="session-a",
        )
        remove_owner_reference_edges(
            artifactctl=ctl,
            owner_type="session",
            owner_id="session-a",
        )

        filters = {"owner_type": "session", "owner_id": "session-a"}
        assert ctl.list_recent(scope_filters=filters) == []
        remaining = ctl.list_recent(
            scope_filters={"owner_type": "session", "owner_id": "session-b"}
        )
        assert [item.sha256 for item in remaining] == [shared.sha256]


def test_remove_owner_rejects_invalid_owner_type(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        with pytest.raises(ArtifactCtlError) as exc_info:
            ctl.ref_remove_owner("unknown", "owner")
        assert exc_info.value.code == "INVALID_ARGUMENT"


def test_refs_remove_owner_cli_uses_configured_store(tmp_path) -> None:
    config_path = write_config_file(tmp_path)
    with ArtifactCtl(str(config_path)) as ctl:
        ref = ctl.ingest_bytes(b"shared", original_name="shared.txt")
        ctl.ref_add("session", "session-a", ref.sha256)

    assert run_cli_command(
        config_path,
        ["refs", "remove-owner", "session", "session-a"],
    ) == {"ok": True}

    with ArtifactCtl(str(config_path)) as ctl:
        assert ctl.index.active_reference_shas() == set()


def test_owner_filters_use_only_active_reference_edges(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        session_a = ctl.ingest_bytes(b"session-a", original_name="shared-a.txt")
        session_b = ctl.ingest_bytes(b"session-b", original_name="shared-b.txt")
        ctl.ref_add("session", "session-a", session_a.sha256)
        ctl.ref_add("session", "session-b", session_b.sha256)

        filters = {"owner_type": "session", "owner_id": "session-a"}
        for rows in (
            ctl.search("shared", filters=filters),
            ctl.list_recent(scope_filters=filters),
            ctl.largest(filters=filters),
        ):
            assert [row.sha256 for row in rows] == [session_a.sha256]

        ctl.ref_remove("session", "session-a", session_a.sha256)
        assert ctl.search("shared", filters=filters) == []


def test_same_content_is_discoverable_through_two_session_edges(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        first = ctl.ingest_bytes(
            b"shared payload",
            original_name="first.txt",
            label="first writer",
        )
        second = ctl.ingest_bytes(
            b"shared payload",
            original_name="second.txt",
            label="second writer",
        )
        assert first.sha256 == second.sha256
        ctl.ref_add("session", "session-a", first.sha256)
        ctl.ref_add("session", "session-b", second.sha256)

        for session_id in ("session-a", "session-b"):
            rows = ctl.list_recent(
                scope_filters={
                    "owner_type": "session",
                    "owner_id": session_id,
                }
            )
            assert [row.sha256 for row in rows] == [first.sha256]

        assert ctl.get(first.sha256).original_name == "first.txt"


def test_normalize_artifact_ref_targets_dedupes_mixed_shapes() -> None:
    sha = "a" * 64
    targets = normalize_artifact_ref_targets(
        [sha_to_ref(sha), {"sha256": sha.upper()}, {"ref": sha_to_ref(sha)}]
    )
    assert targets == [sha]


def test_normalize_artifact_ref_targets_skips_capture_provenance() -> None:
    assert (
        normalize_artifact_ref_targets(
            [
                {
                    "ref": "capture-1",
                    "sha256": "a" * 64,
                    "mime": "application/x-openminion-capture",
                }
            ]
        )
        == []
    )


def test_remove_reference_edges_accepts_mixed_target_shapes(tmp_path) -> None:
    with artifact_ctl(tmp_path) as ctl:
        ref = ctl.ingest_bytes(b"keep", original_name="keep.txt")
        ctl.ref_add("session", "s1", ref.sha256)

        remove_reference_edges(
            artifactctl=ctl,
            owner_type="session",
            owner_id="s1",
            ref_values=[sha_to_ref(ref.sha256), {"sha256": ref.sha256.upper()}],
        )

        assert ref.sha256 not in ctl.index.active_reference_shas()

        ctl.ref_remove("session", "s1", ref.sha256)
        assert ref.sha256 not in ctl.index.active_reference_shas()

        ctl.ref_add("session", "s1", ref.sha256)
        assert ref.sha256 in ctl.index.active_reference_shas()
