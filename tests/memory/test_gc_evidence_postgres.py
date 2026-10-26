"""Memory retention and purge of PostgreSQL items that carry evidence (#400).

``evidence_json`` is JSONB on PostgreSQL, so these steps read it back as a
list. The SQLite controls are in ``test_gc_evidence.py``. The steps run on the
``PostgresMemoryStore`` itself; the ``AuditedMemoryStore`` dispatch is #392.
"""

from __future__ import annotations

import os
from pathlib import Path
import uuid

import pytest
import sqlalchemy as sa

from openminion.modules.memory.storage.postgres.store import PostgresMemoryStore
from tests._memory_evidence_scenarios import (
    CASES,
    RecordingArtifactCtl,
    expected_outcome,
    run_case,
)
from tests.storage.postgres_test_utils import schema_url

pytestmark = pytest.mark.postgres


@pytest.fixture
def postgres_store(tmp_path: Path):
    postgres_url = str(os.environ.get("OPENMINION_TEST_POSTGRES_URL", "")).strip()
    if not postgres_url:
        pytest.skip("OPENMINION_TEST_POSTGRES_URL is not set")
    schema_name = f"sfc_memory_gc_evidence_{uuid.uuid4().hex}"
    admin_engine = sa.create_engine(postgres_url, future=True)
    with admin_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))
    engine = sa.create_engine(schema_url(postgres_url, schema_name), future=True)
    artifactctl = RecordingArtifactCtl()
    store = PostgresMemoryStore(
        engine,
        database_path=tmp_path / ".openminion" / "memory" / "postgres-gc.db",
        artifactctl=artifactctl,
    )
    try:
        yield store, artifactctl
    finally:
        try:
            store.close()
        finally:
            engine.dispose()
            with admin_engine.begin() as conn:
                conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
            admin_engine.dispose()


@pytest.mark.parametrize("case", CASES)
def test_retention_step_removes_postgres_items_with_evidence(
    case: str, postgres_store: tuple[PostgresMemoryStore, RecordingArtifactCtl]
) -> None:
    store, artifactctl = postgres_store
    assert run_case(case, store, artifactctl) == expected_outcome(case)
