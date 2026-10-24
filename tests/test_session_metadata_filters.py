"""Session metadata filters on SQLite (#369).

The PostgreSQL cases run the same scenarios in
`tests/integration/test_runtime_storage_postgres.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from openminion.modules.storage.runtime.context import build_runtime_storage
from openminion.modules.storage.runtime.session_store import SessionStore
from openminion.modules.storage.runtime.session_store.backend import (
    RuntimeSessionStoreBackend,
)
from tests._session_metadata_filter_scenarios import (
    check_acp_session_list,
    check_backend_reading_differences,
    check_focus_directory_sessions,
    check_metadata_filters,
)


@pytest.fixture
def sessions(tmp_path: Path) -> Iterator[SessionStore]:
    storage = build_runtime_storage(tmp_path / "state" / "openminion.db", env={})
    try:
        yield storage.sessions
    finally:
        storage.close()


def test_sqlite_session_metadata_filters_select_json_string_values(
    sessions: SessionStore,
) -> None:
    check_metadata_filters(sessions)


def test_sqlite_session_metadata_filters_read_objects_and_key_paths(
    sessions: SessionStore,
) -> None:
    check_backend_reading_differences(sessions, postgres=False)


def test_sqlite_acp_session_list_filters_by_surface(
    sessions: SessionStore, tmp_path: Path
) -> None:
    check_acp_session_list(sessions, tmp_path / "acp")


def test_sqlite_focus_directory_sessions_filter_by_working_dir(
    sessions: SessionStore, tmp_path: Path
) -> None:
    check_focus_directory_sessions(sessions, tmp_path / "focus")


def test_session_metadata_match_binds_the_key_and_the_value() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        sqlite_backend = RuntimeSessionStoreBackend(connection)
        postgres_backend = RuntimeSessionStoreBackend(
            connection, backend_type="postgres"
        )
        key = "k') OR ('1'='1"
        value = "v' OR '1'='1"

        sqlite_sql, sqlite_params = sqlite_backend.session_metadata_match(key, value)
        postgres_sql, postgres_params = postgres_backend.session_metadata_match(
            key, value
        )

        assert (sqlite_sql, sqlite_params) == (
            "json_extract(metadata_json, ?) = ?",
            [f"$.{key}", value],
        )
        assert (postgres_sql, postgres_params) == (
            "(CAST(metadata_json AS jsonb) -> CAST(? AS text))"
            " = to_jsonb(CAST(? AS text))",
            [key, value],
        )
        with pytest.raises(TypeError, match="must be strings, not int"):
            postgres_backend.session_metadata_match("k", 1)
    finally:
        connection.close()
