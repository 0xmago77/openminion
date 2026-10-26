from __future__ import annotations

import datetime
import os
from collections.abc import Callable
from pathlib import Path
import uuid

import pytest
import sqlalchemy as sa

from openminion.modules.memory.config import RetentionConfig
from openminion.modules.memory.runtime.gc import evict_stale_insights, run_gc
from openminion.modules.memory.models import MemoryCandidate, MemoryRecord
from openminion.modules.memory.storage.postgres.store import PostgresMemoryStore
from tests._memory_retention_scenarios import (
    GC_TARGETS,
    RETENTION_SCENARIOS,
    gc_target,
    memctl_gc_rows,
    run_memctl_gc,
    seed_memctl_gc_records,
)
from tests.storage.postgres_test_utils import schema_url

pytestmark = pytest.mark.postgres


def _now(days_ago: int = 0) -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
    ).isoformat()


def _record(
    record_id: str,
    *,
    scope: str = "agent:lifecycle",
    record_type: str = "fact",
    confidence: float = 0.5,
    age_days: int = 10,
    content: str | dict[str, object] = "content",
    key: str | None = None,
) -> MemoryRecord:
    when = _now(age_days)
    return MemoryRecord(
        id=record_id,
        scope=scope,
        type=record_type,  # type: ignore[arg-type]
        content=content,
        created_at=when,
        updated_at=when,
        confidence=confidence,
        key=key,
        title=record_id,
    )


@pytest.fixture
def postgres_store(tmp_path: Path):
    postgres_url = str(os.environ.get("OPENMINION_TEST_POSTGRES_URL", "")).strip()
    if not postgres_url:
        pytest.skip("OPENMINION_TEST_POSTGRES_URL is not set")
    schema_name = f"sfc_memory_gc_{uuid.uuid4().hex}"
    admin_engine = sa.create_engine(postgres_url, future=True)
    with admin_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))
    engine = sa.create_engine(schema_url(postgres_url, schema_name), future=True)
    store = PostgresMemoryStore(
        engine,
        database_path=tmp_path / ".openminion" / "memory" / "postgres-gc.db",
    )
    try:
        yield store
    finally:
        try:
            store.close()
        finally:
            engine.dispose()
            with admin_engine.begin() as conn:
                conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
            admin_engine.dispose()


@pytest.mark.postgres
def test_postgres_gc_connection_context_manager_yields_usable_connection(
    postgres_store: PostgresMemoryStore,
) -> None:
    with postgres_store.gc_connection() as conn:
        assert conn.execute(sa.text("SELECT 1")).scalar() == 1


@pytest.mark.postgres
def test_postgres_gc_and_retention_paths_round_trip(
    postgres_store: PostgresMemoryStore,
) -> None:
    postgres_store.put(_record("low-old", confidence=0.31, age_days=30))
    for index in range(6):
        postgres_store.put(
            _record(
                f"cap-{index}",
                confidence=0.31 + (index * 0.01),
                age_days=1,
            )
        )
    postgres_store.put(
        _record(
            "summary-old",
            record_type="session_summary",
            confidence=1.0,
            age_days=45,
            key="session_summary:old",
            content={
                "decisions": ["decided to use pytest"],
                "open_questions": ["what remains?"],
                "corrections": ["actually, wrong fixture"],
                "topic_keywords": ["pytest", "fixture"],
                "turn_count": 4,
                "summary_text": "Decided to use pytest. Actually, wrong fixture scope for db setup.",
            },
        )
    )
    postgres_store.put(
        _record(
            "summary-ancient",
            record_type="session_summary",
            age_days=100,
            key="session_summary:ancient",
            content={
                "decisions": ["old decision"],
                "open_questions": [],
                "corrections": [],
                "topic_keywords": ["legacy"],
                "turn_count": 2,
                "summary_text": "Old session to remove.",
            },
        )
    )
    postgres_store.put(
        _record(
            "stale-insight",
            record_type="meta_insight",
            age_days=100,
            content="stale insight",
        )
    )
    postgres_store.put(_record("purge-me", confidence=0.1, age_days=2))
    postgres_store.delete("purge-me")
    postgres_store.candidate_put(
        MemoryCandidate(
            candidate_id="cand-rejected",
            session_id="sess-1",
            proposed_scope="agent:lifecycle",
            type="fact",
            content="stale candidate",
            status="rejected",
        )
    )

    assert evict_stale_insights(postgres_store, staleness_days=60) == 1
    stale_insight = postgres_store.get("stale-insight")
    assert stale_insight is not None
    assert stale_insight.is_deleted is True
    assert stale_insight.deleted_at is not None
    assert stale_insight.deleted_reason == "stale_insight"

    result = run_gc(
        postgres_store,
        retention_config=RetentionConfig(
            enable_soft_delete=True,
            gc_enabled=True,
            gc_batch_size=1000,
            session_summary_max_chars=80,
            summary_compression_age_days=14,
            max_records_per_scope=5,
            confidence_decay_interval_days=7,
            confidence_decay_rate=0.05,
            min_confidence_eviction=0.3,
        ),
    )

    compressed = postgres_store.get("summary-old")
    assert result.decayed_records >= 1
    assert result.capacity_evicted_records >= 1
    assert result.compressed_summaries == 1
    assert result.deleted_candidates == 1
    assert result.deleted_records >= 2
    assert compressed is not None
    assert isinstance(compressed.content, dict)
    assert compressed.content["decisions"] == ["decided to use pytest"]
    assert compressed.content["corrections"] == ["actually, wrong fixture"]
    assert compressed.content["open_questions"] == ["what remains?"]
    assert compressed.content["summary_text"] == "Decided to use pytest"
    assert postgres_store.get("summary-ancient") is None
    assert postgres_store.get("low-old") is None
    assert postgres_store.get("stale-insight") is None
    assert postgres_store.get("purge-me") is None
    assert postgres_store.candidate_get("cand-rejected") is None


@pytest.mark.parametrize("kind", GC_TARGETS)
@pytest.mark.parametrize("scenario", RETENTION_SCENARIOS)
def test_retention_helper_changes_seeded_postgres_records(
    scenario: Callable[..., None],
    kind: str,
    postgres_store: PostgresMemoryStore,
) -> None:
    # The runtime session lifecycle passes its AuditedMemoryStore (#392).
    target, sink = gc_target(kind, postgres_store)
    scenario(target, postgres_store, sink)


def test_memctl_gc_with_a_typed_postgres_config(
    postgres_store: PostgresMemoryStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # memctl builds its own AuditedMemoryStore over a PostgreSQL store from the
    # typed config; the purge runs on the store it wraps (#401).
    seed_memctl_gc_records(postgres_store)
    url = postgres_store._engine.url.render_as_string(hide_password=False)

    result = run_memctl_gc(
        tmp_path, monkeypatch, {"backend": "postgres", "postgres": {"url": url}}
    )

    assert result.exit_code == 0, result.output
    assert "GC: deleted_records=1, deleted_candidates=0" in result.stdout
    assert memctl_gc_rows(postgres_store) == {"old": (0.6, False), "deleted": None}
