from __future__ import annotations

import logging
from pathlib import Path

from openminion.modules.artifact.config import (
    ArtifactCtlConfig,
    BlobStoreConfig,
    IndexConfig,
    ViewsConfig,
)
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.brain.adapters.context.bridges.artifact import (
    BridgeArtifactClient,
)


class _FailingArtifactCtl:
    def search(self, **_kwargs):
        raise RuntimeError("db exploded")


def test_bridge_client_logs_on_db_error(caplog) -> None:
    bridge = BridgeArtifactClient(artifact_ctl=_FailingArtifactCtl())

    caplog.set_level(logging.WARNING)
    result = bridge.query_digests(
        session_id="sess-1",
        agent_id="agent-1",
        query="hello",
        limit=5,
    )

    assert result == []
    assert "artifact query_digests failed: db exploded" in caplog.text


def test_bridge_client_returns_owned_canonical_digest(tmp_path: Path) -> None:
    root = tmp_path / ".openminion" / "artifact"
    config = ArtifactCtlConfig(
        blob_store=BlobStoreConfig(root_dir=str(root)),
        index=IndexConfig(sqlite_path=str(root / "index.db")),
    )
    with ArtifactCtl(config) as artifactctl:
        first = artifactctl.ingest_bytes(
            b"session alpha user@example.com evidence",
            mime="text/plain",
            label="shared session note",
        )
        second = artifactctl.ingest_bytes(
            b"session beta evidence", mime="text/plain", label="shared session note"
        )
        artifactctl.ref_add("session", "session-a", first.sha256)
        artifactctl.ref_add("session", "session-b", second.sha256)
        bridge = BridgeArtifactClient(artifact_ctl=artifactctl)

        result = bridge.query_digests(
            session_id="session-a",
            agent_id="agent-1",
            query="session",
            limit=5,
        )

        assert len(result) == 1
        digest = result[0]
        assert digest.ref == first.ref
        assert digest.view_id == f"artifact://sha256/{digest.digest_hash}"
        assert "session alpha [REDACTED_EMAIL] evidence" in str(digest.excerpt)

        artifactctl.ref_remove("session", "session-a", first.sha256)
        assert (
            bridge.query_digests(
                session_id="session-a",
                agent_id="agent-1",
                query="session",
                limit=5,
            )
            == []
        )


def test_bridge_client_skips_missing_selected_artifact_without_filling_limit(
    tmp_path: Path,
    caplog,
) -> None:
    root = tmp_path / ".openminion" / "artifact"
    config = ArtifactCtlConfig(
        blob_store=BlobStoreConfig(root_dir=str(root)),
        index=IndexConfig(sqlite_path=str(root / "index.db")),
        views=ViewsConfig(auto_generate=[]),
    )
    with ArtifactCtl(config) as artifactctl:
        outside_limit = artifactctl.ingest_bytes(
            b"session outside limit",
            mime="text/plain",
            label="shared session bridge note",
        )
        healthy = artifactctl.ingest_bytes(
            b"session healthy evidence",
            mime="text/plain",
            label="shared session bridge note",
        )
        missing = artifactctl.ingest_bytes(
            b"session missing evidence",
            mime="text/plain",
            label="shared session bridge note",
        )
        for ref in (outside_limit, healthy, missing):
            artifactctl.ref_add("session", "session-a", ref.sha256)
        artifactctl.blob_store.delete(missing.sha256)
        bridge = BridgeArtifactClient(artifact_ctl=artifactctl)

        with caplog.at_level(logging.WARNING):
            result = bridge.query_digests(
                session_id="session-a",
                agent_id="agent-1",
                query="session",
                limit=2,
            )

        assert [item.ref for item in result] == [healthy.ref]
        assert outside_limit.ref not in {item.ref for item in result}
        assert caplog.text.count("artifact digest skipped") == 1
        assert missing.ref in caplog.text


def test_bridge_client_isolates_raw_backend_failure(
    tmp_path: Path,
    caplog,
    monkeypatch,
) -> None:
    root = tmp_path / ".openminion" / "artifact"
    config = ArtifactCtlConfig(
        blob_store=BlobStoreConfig(root_dir=str(root)),
        index=IndexConfig(sqlite_path=str(root / "index.db")),
    )
    with ArtifactCtl(config) as artifactctl:
        healthy = artifactctl.ingest_bytes(
            b"session healthy backend evidence",
            mime="text/plain",
            label="shared session backend note",
        )
        failing = artifactctl.ingest_bytes(
            b"session failing backend evidence",
            mime="text/plain",
            label="shared session backend note",
        )
        for ref in (healthy, failing):
            artifactctl.ref_add("session", "session-a", ref.sha256)
        ensure_digest = artifactctl.ensure_digest

        def _raise_for_failing(ref_or_sha, policy=None):
            if ref_or_sha == failing.sha256:
                raise OSError("backend read failed")
            return ensure_digest(ref_or_sha, policy=policy)

        monkeypatch.setattr(artifactctl, "ensure_digest", _raise_for_failing)
        bridge = BridgeArtifactClient(artifact_ctl=artifactctl)

        with caplog.at_level(logging.WARNING):
            result = bridge.query_digests(
                session_id="session-a",
                agent_id="agent-1",
                query="session",
                limit=2,
            )

        assert [item.ref for item in result] == [healthy.ref]
        assert "OSError" in caplog.text
        assert failing.ref in caplog.text
