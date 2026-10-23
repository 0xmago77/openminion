from __future__ import annotations

import concurrent.futures
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote_plus
import uuid
from unittest.mock import patch

import pytest

from openminion.modules.storage.runtime.context import build_runtime_storage
from openminion.modules.storage.runtime.idempotency_store import IdempotencyStore
from openminion.modules.storage.runtime.migrations import (
    DEFAULT_MIGRATIONS,
    migrate_record_store,
)
from openminion.modules.storage.runtime.session_store import SessionStore
from openminion.modules.task.run import (
    resolve_invocation_terminal,
    resolve_thread_lifecycle,
)

pytestmark = pytest.mark.postgres


def _schema_url(base_url: str, schema_name: str) -> str:
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}options={quote_plus(f'-csearch_path={schema_name}')}"


@pytest.mark.postgres
def test_build_runtime_storage_supports_postgres_backend(tmp_path: Path) -> None:
    postgres_url = str(os.getenv("OPENMINION_TEST_POSTGRES_URL", "")).strip()
    if not postgres_url:
        pytest.skip("OPENMINION_TEST_POSTGRES_URL is not set")

    sqlalchemy = pytest.importorskip("sqlalchemy")
    schema_name = f"ssew_runtime_{uuid.uuid4().hex}"
    admin_engine = sqlalchemy.create_engine(postgres_url, future=True)
    with admin_engine.begin() as conn:
        conn.execute(sqlalchemy.text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))

    runtime_storage = build_runtime_storage(
        tmp_path / "state" / "openminion.db",
        env={},
        record_backend="record.postgres",
        record_backend_options={"url": _schema_url(postgres_url, schema_name)},
    )
    try:
        assert isinstance(runtime_storage.sessions, SessionStore)
        assert isinstance(runtime_storage.idempotency, IdempotencyStore)
        assert runtime_storage.migration_result.current_version >= 1

        session = runtime_storage.sessions.resolve_session(
            agent_id="hello-agent",
            channel="console",
            target="postgres-runtime",
        )
        runtime_storage.sessions.append_message(
            session_id=session.id,
            role="inbound",
            body="hello",
            metadata={"source": "postgres"},
        )
        messages = runtime_storage.sessions.list_recent_messages(
            session_id=session.id,
            limit=5,
        )
        reserved = runtime_storage.idempotency.reserve(
            method="turn.send",
            idempotency_key="postgres-key",
            request_hash="h1",
        )
        record = runtime_storage.idempotency.get(
            method="turn.send",
            idempotency_key="postgres-key",
        )

        assert messages
        assert messages[0].body == "hello"
        assert reserved is True
        assert record is not None
        assert record.status == "in_progress"

        fixed_time = "2026-08-11T00:00:00+00:00"
        with patch(
            "openminion.modules.storage.runtime.session_store.lifecycle.utc_now_iso",
            return_value=fixed_time,
        ):
            first_event = runtime_storage.sessions.append_event(
                session_id=session.id,
                event_type="run.queued",
                payload={
                    "run_id": "run-first",
                    "state": "queued",
                    "thread_id": "thread-first",
                    "invocation_id": "invocation-first",
                },
            )
            second_event = runtime_storage.sessions.append_event(
                session_id=session.id,
                event_type="run.queued",
                payload={"run_id": "run-second", "state": "queued"},
            )
        assert first_event.id != second_event.id
        assert first_event.payload["run_id"] == "run-first"
        assert second_event.payload["run_id"] == "run-second"

        runtime_storage.record_store.insert_many(
            "events",
            [
                {
                    "session_id": session.id,
                    "event_type": "noise",
                    "payload_json": json.dumps(
                        {"index": index, "thread_id": "thread-first"}
                    ),
                    "created_at": fixed_time,
                }
                for index in range(2001)
            ],
        )
        projection = resolve_thread_lifecycle(
            runtime_storage.sessions,
            session_id=session.id,
            thread_id="thread-first",
        )
        assert projection.invocation_id == "invocation-first"
        assert projection.invocation_source_event_id == first_event.id

        runtime_storage.sessions.append_event(
            session_id=session.id,
            event_type="response.persisted",
            payload={"run_id": "run-first", "thread_id": "thread-first"},
        )
        runtime_storage.sessions.append_event(
            session_id=session.id,
            event_type="response.delivered",
            payload={"run_id": "run-first", "thread_id": "thread-first"},
        )
        terminal_source = runtime_storage.sessions.append_event(
            session_id=session.id,
            event_type="run.completed",
            payload={
                "run_id": "run-first",
                "state": "completed",
                "thread_id": "thread-first",
            },
        )
        terminal = resolve_invocation_terminal(
            runtime_storage.sessions,
            session_id=session.id,
            trigger_event=terminal_source,
            thread_id="thread-first",
        )
        assert terminal is not None
        assert terminal.invocation_id == "invocation-first"
        assert terminal.resolved_state == "settled"
        assert terminal.source_event_id == terminal_source.id

        before_page = runtime_storage.sessions.list_events_before_id(
            session_id=session.id,
            before_id=second_event.id + 1,
            limit=2,
        )
        assert [event.id for event in before_page] == [
            second_event.id,
            first_event.id,
        ]

        peer_storages = [
            build_runtime_storage(
                tmp_path / f"state/peer-{index}.db",
                env={},
                record_backend="record.postgres",
                record_backend_options={"url": _schema_url(postgres_url, schema_name)},
            )
            for index in range(4)
        ]
        try:
            with patch(
                "openminion.modules.storage.runtime.session_store.lifecycle.utc_now_iso",
                return_value=fixed_time,
            ):
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    concurrent_rows = list(
                        pool.map(
                            lambda pair: pair[1].sessions.append_event(
                                session_id=session.id,
                                event_type="run.queued",
                                payload={"run_id": f"parallel-{pair[0]}"},
                            ),
                            enumerate(peer_storages),
                        )
                    )
            assert len({event.id for event in concurrent_rows}) == 4
            assert {event.payload["run_id"] for event in concurrent_rows} == {
                f"parallel-{index}" for index in range(4)
            }
        finally:
            for peer_storage in peer_storages:
                peer_storage.close()
    finally:
        try:
            runtime_storage.close()
        finally:
            with admin_engine.begin() as conn:
                conn.execute(
                    sqlalchemy.text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE')
                )
            admin_engine.dispose()


MESSAGE_CLOCK = "openminion.modules.storage.runtime.session_store.messages.utc_now_iso"
MESSAGE_UUID = "openminion.modules.storage.runtime.session_store.messages.uuid4"
TIED_AT = "2026-10-22T01:00:00+00:00"


@contextmanager
def _postgres_schema(prefix: str) -> Iterator[str]:
    postgres_url = str(os.getenv("OPENMINION_TEST_POSTGRES_URL", "")).strip()
    if not postgres_url:
        pytest.skip("OPENMINION_TEST_POSTGRES_URL is not set")
    sqlalchemy = pytest.importorskip("sqlalchemy")
    schema_name = f"{prefix}_{uuid.uuid4().hex}"
    admin_engine = sqlalchemy.create_engine(postgres_url, future=True)
    with admin_engine.begin() as conn:
        conn.execute(sqlalchemy.text(f'CREATE SCHEMA "{schema_name}"'))
    try:
        yield _schema_url(postgres_url, schema_name)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(
                sqlalchemy.text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE')
            )
        admin_engine.dispose()


@pytest.mark.postgres
def test_postgres_messages_keep_append_order_on_tied_timestamps(
    tmp_path: Path,
) -> None:
    sqlalchemy = pytest.importorskip("sqlalchemy")
    with _postgres_schema("om353_order") as url:
        storage = build_runtime_storage(
            tmp_path / "state" / "openminion.db",
            env={},
            record_backend="record.postgres",
            record_backend_options={"url": url},
        )
        try:
            sessions = storage.sessions
            session = sessions.resolve_session(
                agent_id="main", channel="console", target="tied"
            )
            specs = (
                ("inbound", "conv-a", "thread-a"),
                ("outbound", "conv-a", "thread-a"),
                ("inbound", "conv-b", "thread-b"),
                ("outbound", "conv-b", "thread-b"),
            )
            with (
                patch(MESSAGE_CLOCK, return_value=TIED_AT),
                patch(
                    MESSAGE_UUID,
                    side_effect=[SimpleNamespace(hex=c * 32) for c in "fc80"],
                ),
            ):
                appended = [
                    sessions.append_message(
                        session_id=session.id,
                        conversation_id=conversation_id,
                        thread_id=thread_id,
                        role=role,
                        body=f"{conversation_id}/{role}",
                    )
                    for role, conversation_id, thread_id in specs
                ]
            ids = [item.id for item in appended]

            listed = sessions.list_messages(session_id=session.id)
            assert [item.id for item in listed] == ids
            assert [item.rowid for item in appended] == [1, 2, 3, 4]
            assert {item.created_at for item in listed} == {TIED_AT}
            assert [
                item.id
                for item in sessions.list_recent_messages(
                    session_id=session.id, limit=1
                )
            ] == ids[3:]
            assert [
                item.id
                for item in sessions.list_recent_messages(
                    session_id=session.id, conversation_id="conv-a", limit=1
                )
            ] == ids[1:2]
            assert [
                item.id
                for item in sessions.list_messages(
                    session_id=session.id,
                    conversation_id="conv-b",
                    thread_id="thread-b",
                )
            ] == ids[2:]
            assert sessions.latest_conversation_id(session_id=session.id) == "conv-b"
            assert [
                item.id
                for item in sessions.list_messages_after_rowid(
                    session_id=session.id, after_rowid=appended[0].rowid
                )
            ] == ids[1:]

            # A failed append rolls back the session write and its append_seq.
            before = sessions.get_session(session.id)
            with (
                patch(MESSAGE_CLOCK, return_value="2026-10-22T01:00:01+00:00"),
                patch(MESSAGE_UUID, return_value=SimpleNamespace(hex=ids[0])),
            ):
                with pytest.raises(sqlalchemy.exc.IntegrityError):
                    sessions.append_message(
                        session_id=session.id, role="inbound", body="duplicate id"
                    )
            after = sessions.get_session(session.id)
            assert before is not None and after is not None
            assert (after.updated_at, after.last_activity_at) == (
                before.updated_at,
                before.last_activity_at,
            )
            with patch(MESSAGE_CLOCK, return_value=TIED_AT):
                fifth = sessions.append_message(
                    session_id=session.id, role="inbound", body="fifth"
                )
            assert fifth.rowid == 5
            seq_rows = storage.record_store.query_dicts(
                "SELECT id, append_seq FROM messages WHERE session_id = ?",
                (session.id,),
            )
            assert sorted(int(row["append_seq"]) for row in seq_rows) == [1, 2, 3, 4, 5]

            # Concurrent appends to one session allocate one order.
            peers = [
                build_runtime_storage(
                    tmp_path / f"state/peer-{index}.db",
                    env={},
                    record_backend="record.postgres",
                    record_backend_options={"url": url},
                )
                for index in range(4)
            ]
            barrier = threading.Barrier(len(peers))

            def _append_ten(peer: Any) -> list[Any]:
                barrier.wait()
                return [
                    peer.sessions.append_message(
                        session_id=session.id, role="inbound", body=f"peer-{step}"
                    )
                    for step in range(10)
                ]

            try:
                with patch(MESSAGE_CLOCK, return_value=TIED_AT):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                        per_peer = list(pool.map(_append_ten, peers))
            finally:
                for peer in peers:
                    peer.close()
            records = [item for items in per_peer for item in items]
            assert sorted(item.rowid for item in records) == list(range(6, 46))
            for items in per_peer:
                assert [item.rowid for item in items] == sorted(
                    item.rowid for item in items
                )
            assert [
                item.id for item in sessions.list_messages(session_id=session.id)
            ] == [*ids, fifth.id] + [
                item.id for item in sorted(records, key=lambda item: item.rowid)
            ]
        finally:
            storage.close()


@pytest.mark.postgres
def test_postgres_append_seq_migration_uses_fallback_order_and_moves_tied_boundary(
    tmp_path: Path,
) -> None:
    pytest.importorskip("sqlalchemy")
    from openminion.modules.storage.backends.postgres import RecordStorePostgres

    with _postgres_schema("om353_upgrade") as url:
        record_store = RecordStorePostgres(url)
        try:
            migrate_record_store(
                record_store,
                backend_type="postgres",
                migrations=tuple(
                    item for item in DEFAULT_MIGRATIONS if item.version < 12
                ),
            )
            record_store.execute_count(
                "INSERT INTO sessions(id, session_key, channel, target) "
                "VALUES ('s', 'key-s', 'console', 's')"
            )
            # Append order; g1-g4 share created_at with ids in reverse order.
            for message_id, body, created_at in (
                ("5" * 32, "e0", "2026-10-22T00:59:00+00:00"),
                ("f" * 32, "g1", TIED_AT),
                ("c" * 32, "g2", TIED_AT),
                ("8" * 32, "g3", TIED_AT),
                ("0" * 32, "g4", TIED_AT),
                ("4" * 32, "l1", "2026-10-22T01:01:00+00:00"),
            ):
                record_store.execute_count(
                    "INSERT INTO messages(id, session_id, role, body, created_at) "
                    "VALUES (?, 's', 'inbound', ?, ?)",
                    (message_id, body, created_at),
                )
            record_store.execute_count(
                "INSERT INTO session_contexts(session_id, rolling_summary, "
                "compacted_until_rowid, compacted_until_created_at, "
                "compacted_until_message_id, compacted_message_count) "
                "VALUES ('s', 'summary of e0, g3', 2, ?, ?, 2)",
                (TIED_AT, "8" * 32),
            )

            result = migrate_record_store(record_store, backend_type="postgres")
            assert result.applied_versions == (12,)

            seq_rows = record_store.query_dicts(
                "SELECT body, append_seq FROM messages ORDER BY append_seq"
            )
            # Postgres stored no insertion order: the backfill keeps the
            # pre-upgrade (created_at, id) read order.
            assert [(row["body"], int(row["append_seq"])) for row in seq_rows] == [
                ("e0", 1),
                ("g4", 2),
                ("g3", 3),
                ("g2", 4),
                ("g1", 5),
                ("l1", 6),
            ]
            store = SessionStore(record_store)
            context = store.get_session_context(session_id="s")
            assert context is not None
            assert (
                context.compacted_until_rowid,
                context.compacted_until_created_at,
                context.compacted_until_message_id,
                context.compacted_message_count,
                context.rolling_summary,
            ) == (1, "2026-10-22T00:59:00+00:00", "5" * 32, 1, "summary of e0, g3")
            assert [
                item.body
                for item in store.list_messages_after_rowid(
                    session_id="s", after_rowid=context.compacted_until_rowid
                )
            ] == ["g4", "g3", "g2", "g1", "l1"]
            with patch(MESSAGE_CLOCK, return_value=TIED_AT):
                appended = store.append_message(
                    session_id="s", role="inbound", body="after-upgrade"
                )
            assert appended.rowid == 6
            assert [item.body for item in store.list_messages(session_id="s")] == [
                "e0",
                "g4",
                "g3",
                "g2",
                "g1",
                "after-upgrade",
                "l1",
            ]
        finally:
            record_store.close()
