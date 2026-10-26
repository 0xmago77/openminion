"""Retention helpers on SQLite, on the store and through ``AuditedMemoryStore``.

The runtime session lifecycle passes its audited store to these helpers. The
PostgreSQL cases are in ``test_gc_postgres.py`` (#392).
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
)


@pytest.mark.parametrize("kind", GC_TARGETS)
@pytest.mark.parametrize("scenario", RETENTION_SCENARIOS)
def test_retention_helper_changes_seeded_sqlite_records(
    scenario: Callable[..., None], kind: str, tmp_path: Path
) -> None:
    store = SQLiteMemoryStore(tmp_path / "memory.db")
    target, sink = gc_target(kind, store)
    scenario(target, store, sink)
