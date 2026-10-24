from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from openminion.modules.storage.record_store import RecordStore

from .models import MessageRecord
from .rows import MESSAGE_COLUMNS, row_to_message


class RuntimeSessionStoreBackend:
    def __init__(
        self,
        store_or_connection: RecordStore | sqlite3.Connection,
        *,
        backend_type: str = "sqlite",
    ) -> None:
        if isinstance(store_or_connection, sqlite3.Connection):
            self._record_store: RecordStore | None = None
            self._conn: sqlite3.Connection | None = store_or_connection
        else:
            self._record_store = store_or_connection
            self._conn = None
        self._raw_tx_depth = 0
        self._backend_type = str(backend_type or "").strip().lower() or "sqlite"

    def session_metadata_match(self, key: str, value: str) -> tuple[str, list[str]]:
        """Return SQL and parameters for one session metadata filter condition.

        `list_sessions(metadata_filter=...)` selects the sessions whose
        `metadata_json` holds `value` at `key`; both are bound as parameters.
        SQLite compares `json_extract(metadata_json, '$.<key>')` with `value`,
        as it always has. PostgreSQL compares JSON values instead of text:
        `CAST(metadata_json AS jsonb) -> key` must equal the JSON string
        `value`, so a number, a boolean or JSON null is never read as its text.
        On both, a JSON string equal to `value` matches, and a missing key,
        JSON null, a number or a boolean does not.

        The backends differ where SQLite reads more than a top-level string.
        `json_extract` returns an object or array as its minified JSON text,
        which `value` can equal, and reads `key` as a JSON path: `a.b` is `b`
        inside `a`, `[` starts an array index and a leading `"` quotes the key.
        PostgreSQL reads `key` as one top-level key and matches strings only.
        PostgreSQL raises for a stored document that `jsonb` cannot hold: NaN
        or Infinity, which `json.dumps` writes and SQLite before 3.42 also
        rejects, an escaped NUL or an unpaired surrogate. It also raises for a
        NUL in `value` and for a `value` that is not a string, which it does
        not convert to text.

        `backend_type` is the one `build_runtime_storage` gives
        `migrate_record_store`.
        """
        if self._backend_type == "postgres":
            if not isinstance(value, str):
                raise TypeError(
                    "session metadata filter values must be strings, "
                    f"not {type(value).__name__}"
                )
            return (
                "(CAST(metadata_json AS jsonb) -> CAST(? AS text))"
                " = to_jsonb(CAST(? AS text))",
                [key, value],
            )
        return "json_extract(metadata_json, ?) = ?", [f"$.{key}", value]

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self._record_store is not None:
            with self._record_store.transaction():
                yield
            return

        if self._conn is None:
            raise RuntimeError("session store has no backing connection")
        self._raw_tx_depth += 1
        if self._raw_tx_depth == 1:
            self._conn.execute("BEGIN")
        try:
            yield
        except Exception:
            if self._raw_tx_depth == 1:
                self._conn.rollback()
            raise
        else:
            if self._raw_tx_depth == 1:
                self._conn.commit()
        finally:
            self._raw_tx_depth -= 1

    def query_dicts(
        self,
        sql: str,
        params: tuple[Any, ...] | list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        if self._record_store is not None:
            return self._record_store.query_dicts(sql, params)
        if self._conn is None:
            raise RuntimeError("session store has no backing connection")
        rows = self._conn.execute(sql, params or ()).fetchall()
        return [dict(row) for row in rows]

    def query_one(
        self,
        sql: str,
        params: tuple[Any, ...] | list[Any] | None = None,
    ) -> dict[str, Any] | None:
        rows = self.query_dicts(sql, params)
        return rows[0] if rows else None

    def execute_count(
        self,
        sql: str,
        params: tuple[Any, ...] | list[Any] | None = None,
    ) -> int:
        if self._record_store is not None:
            return self._record_store.execute_count(sql, params)
        if self._conn is None:
            raise RuntimeError("session store has no backing connection")
        cursor = self._conn.execute(sql, params or ())
        if self._raw_tx_depth == 0:
            self._conn.commit()
        return int(cursor.rowcount or 0)

    def insert(self, table: str, row: dict[str, Any]) -> int:
        if self._record_store is not None:
            return self._record_store.insert(table, row)
        if self._conn is None:
            raise RuntimeError("session store has no backing connection")
        columns = list(row)
        placeholders = ", ".join("?" for _ in columns)
        quoted = ", ".join(f'"{column}"' for column in columns)
        cursor = self._conn.execute(
            f'INSERT INTO "{table}" ({quoted}) VALUES ({placeholders})',
            tuple(row[column] for column in columns),
        )
        if self._raw_tx_depth == 0:
            self._conn.commit()
        inserted_id = int(cursor.lastrowid or 0)
        if inserted_id <= 0:
            raise RuntimeError(f"insert did not return a row ID for {table}")
        return inserted_id

    def message_query(
        self,
        *,
        where_clause: str,
        params: list[object],
        newest_first: bool,
        limit: int,
        after_rowid: int | None = None,
    ) -> list[dict[str, Any]]:
        """Read messages in their one session order.

        A session's messages are ordered by `created_at`, then by
        `append_seq`, the per-session sequence `append_message` allocates, so
        messages stored with the same `created_at` keep append order. The
        returned `rowid` is the 1-based position in that order across the whole
        session; conversation and thread filters do not renumber it.
        """
        outer_where = [where_clause.replace("WHERE ", "", 1)]
        outer_params = list(params)
        if after_rowid is not None:
            outer_where.append("rowid > ?")
            outer_params.append(max(0, int(after_rowid)))
        outer_sql = "WHERE " + " AND ".join(outer_where)
        direction = "DESC" if newest_first else "ASC"
        query = f"""
            SELECT rowid, {MESSAGE_COLUMNS}
            FROM (
                SELECT
                    ROW_NUMBER() OVER (
                        PARTITION BY session_id
                        ORDER BY created_at ASC, append_seq ASC
                    ) AS rowid,
                    {MESSAGE_COLUMNS}
                FROM messages
            ) AS numbered
            {outer_sql}
            ORDER BY rowid {direction}
            LIMIT ?
        """
        outer_params.append(max(0, int(limit)))
        return self.query_dicts(query, outer_params)

    def message_by_id(self, message_id: str) -> MessageRecord:
        row = self.query_one(
            f"""
            SELECT rowid, {MESSAGE_COLUMNS}
            FROM (
                SELECT
                    ROW_NUMBER() OVER (
                        PARTITION BY session_id
                        ORDER BY created_at ASC, append_seq ASC
                    ) AS rowid,
                    {MESSAGE_COLUMNS}
                FROM messages
            ) AS numbered
            WHERE id = ?
            """,
            (message_id,),
        )
        if row is None:
            raise RuntimeError(f"Failed to load message after insert: {message_id}")
        return row_to_message(row)
