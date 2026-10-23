from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from openminion.modules.storage.record_store import RecordStore

from .models import MessageRecord
from .rows import MESSAGE_COLUMNS, row_to_message

_PAYLOAD_KEY = re.compile(r"[a-z_]+")
# The characters Python's `str.strip()` removes: those whose `isspace()` is true.
_STRIP_CODE_POINTS = (
    *range(9, 14),
    *range(28, 33),
    133,
    160,
    5760,
    *range(8192, 8203),
    8232,
    8233,
    8239,
    8287,
    12288,
)


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

    def strip_text(self, expression: str) -> str:
        """Return SQL that strips `expression` as Python's `str.strip()` does.

        SQL `TRIM` without a character set removes spaces only; this removes
        every character `str.isspace()` accepts, from both ends.
        """
        if self._backend_type == "postgres":
            chars = " || ".join(f"CHR({code})" for code in _STRIP_CODE_POINTS)
            return f"BTRIM({expression}, {chars})"
        chars = ", ".join(str(code) for code in _STRIP_CODE_POINTS)
        return f"TRIM({expression}, char({chars}))"

    def payload_text(
        self, key: str, *, null: str = "None", falsy_empty: bool = False
    ) -> str:
        """Return SQL for `str(payload.get(key, "")).strip()` of `events.payload_json`.

        It reads the top-level `key` as the run status readers do in Python: a
        missing key is "", a string is stripped as `str.strip()` strips it, JSON
        null is `null` ("None", or "" for a reader that maps None to ""), a
        boolean is "True" or "False", and a number, object or array is its JSON
        text. With `falsy_empty` a value Python treats as false (null, false, 0,
        "", {} or []) is "", as in `str(payload.get(key) or "").strip()`. Strings
        are read exactly. A float is never empty, but its text can differ from
        Python's: SQLite writes 1e16 as 1.0e+16.

        `metadata_json` can also store NaN and Infinity, which are not JSON, and
        a NUL in a string, which Postgres cannot return as text. These are read
        as stored, not substituted: Postgres and SQLite before 3.42 reject a
        payload with NaN or Infinity, newer SQLite reads NaN as null, and
        Postgres rejects a payload with a NUL in any string.

        `backend_type` is the one `build_runtime_storage` gives
        `migrate_record_store`. SQLite reads the stored JSON with `json_type` and
        `json_extract`; Postgres casts it to `json` and reads it with
        `json_typeof`, `->` and `->>`. `key` is a fixed payload key from this
        package; values are bound as parameters.
        """
        if not _PAYLOAD_KEY.fullmatch(key):
            raise ValueError(f"Invalid payload key: {key!r}")
        if null not in ("None", ""):
            raise ValueError(f"Invalid null text: {null!r}")
        null_text = "" if falsy_empty else null
        false_text = "" if falsy_empty else "False"
        if self._backend_type == "postgres":
            document = "CAST(payload_json AS json)"
            value = f"({document} ->> '{key}')"
            other = value
            if falsy_empty:
                falsy = "'0', '0.0', '-0.0', '{}', '[]'"
                other = f"CASE WHEN {value} IN ({falsy}) THEN '' ELSE {value} END"
            return (
                f"COALESCE(CASE json_typeof({document} -> '{key}')"
                f" WHEN 'string' THEN {self.strip_text(value)}"
                f" WHEN 'null' THEN '{null_text}'"
                f" WHEN 'boolean' THEN CASE {value} WHEN 'true' THEN 'True'"
                f" ELSE '{false_text}' END"
                f" ELSE {other} END, '')"
            )
        path = f"'$.{key}'"
        value = f"json_extract(payload_json, {path})"
        other = f"CAST({value} AS TEXT)"
        if falsy_empty:
            other = f"CASE WHEN {value} IN (0, '{{}}', '[]') THEN '' ELSE {other} END"
        return (
            f"COALESCE(CASE json_type(payload_json, {path})"
            f" WHEN 'text' THEN {self.strip_text(value)}"
            f" WHEN 'null' THEN '{null_text}'"
            f" WHEN 'true' THEN 'True'"
            f" WHEN 'false' THEN '{false_text}'"
            f" ELSE {other} END, '')"
        )

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
