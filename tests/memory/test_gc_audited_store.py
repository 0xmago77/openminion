"""Retention helpers on SQLite, on the store and through ``AuditedMemoryStore``.

The runtime session lifecycle passes its audited store to these helpers. The
PostgreSQL cases are in ``test_gc_postgres.py`` (#392). The purge scenario and
the ``memctl gc`` run with a typed config cover the purge entry point (#401).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from openminion.modules.memory.storage.sqlite.store import SQLiteMemoryStore
from tests._memory_retention_scenarios import (
    GC_TARGETS,
    RETENTION_SCENARIOS,
    gc_target,
    memctl_gc_rows,
    run_memctl_gc,
    seed_memctl_gc_records,
)


@pytest.mark.parametrize("kind", GC_TARGETS)
@pytest.mark.parametrize("scenario", RETENTION_SCENARIOS)
def test_retention_helper_changes_seeded_sqlite_records(
    scenario: Callable[..., None], kind: str, tmp_path: Path
) -> None:
    store = SQLiteMemoryStore(tmp_path / "memory.db")
    target, sink = gc_target(kind, store)
    scenario(target, store, sink)


def test_memctl_gc_with_a_typed_sqlite_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "data" / "memory" / "memory.db"
    store = SQLiteMemoryStore(db_path)
    try:
        seed_memctl_gc_records(store)
    finally:
        store.close()

    result = run_memctl_gc(
        tmp_path, monkeypatch, {"backend": "sqlite", "sqlite_path": str(db_path)}
    )

    assert result.exit_code == 0, result.output
    assert "GC: deleted_records=1, deleted_candidates=0" in result.stdout
    store = SQLiteMemoryStore(db_path)
    try:
        assert memctl_gc_rows(store) == {"old": (0.6, False), "deleted": None}
    finally:
        store.close()
