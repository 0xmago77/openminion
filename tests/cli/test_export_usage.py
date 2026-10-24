from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from openminion.base.config import OpenMinionConfig, save_config
from openminion.cli.commands.export import run_export
from openminion.modules.storage import build_runtime_storage
from openminion.modules.storage.runtime.session_store import SessionStore
from tests._csc_fixtures import _csc_install_default_agent


def test_jsonl_transcript_exposes_public_usage_without_parsing_metadata(
    tmp_path, capsys
) -> None:
    database_path = tmp_path / "state" / "openminion.db"
    config_path = tmp_path / "config.json"
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider="echo")
    config.storage.path = str(database_path)
    save_config(config, str(config_path))

    storage = build_runtime_storage(database_path)
    try:
        session = storage.sessions.resolve_session(
            agent_id="openminion",
            channel="console",
            target="focus",
            session_id="usage-session",
        )
        storage.sessions.append_message(
            session_id=session.id,
            role="outbound",
            body="reply",
            metadata={
                "run_stats_json": json.dumps(
                    {
                        "input_tokens": 12,
                        "output_tokens": 3,
                        "llm_calls": 1,
                    }
                ),
                "private": "not-a-public-contract",
            },
        )
    finally:
        storage.close()

    result = run_export(
        SimpleNamespace(
            config=str(config_path),
            session_id="usage-session",
            format="jsonl",
            output="",
            include_events=False,
        )
    )

    assert result == 0
    record = json.loads(capsys.readouterr().out)
    assert record["stats"]["input_tokens"] == 12
    assert record["stats"]["output_tokens"] == 3
    assert record["stats"]["llm_calls"] == 1


MESSAGE_CLOCK = "openminion.modules.storage.runtime.session_store.messages.utc_now_iso"
MESSAGE_UUID = "openminion.modules.storage.runtime.session_store.messages.uuid4"
EVENT_CLOCK = "openminion.modules.storage.runtime.session_store.lifecycle.utc_now_iso"
TIED_AT = "2026-10-22T01:00:00+00:00"


@contextmanager
def _clock(created_at: str) -> Iterator[None]:
    with (
        patch(MESSAGE_CLOCK, return_value=created_at),
        patch(EVENT_CLOCK, return_value=created_at),
    ):
        yield


def _write_session(tmp_path, write: Callable[[SessionStore, str], None]) -> str:
    """Fill one runtime session with `write`; return the config path to export it."""
    database_path = tmp_path / "state" / "openminion.db"
    config_path = tmp_path / "config.json"
    config = OpenMinionConfig()
    _csc_install_default_agent(config, provider="echo")
    config.storage.path = str(database_path)
    save_config(config, str(config_path))

    storage = build_runtime_storage(database_path)
    try:
        session = storage.sessions.resolve_session(
            agent_id="openminion",
            channel="console",
            target="focus",
            session_id="tied-session",
        )
        write(storage.sessions, session.id)
    finally:
        storage.close()
    return str(config_path)


def _export(config_path: str, capsys, *, out_format: str = "jsonl") -> str:
    result = run_export(
        SimpleNamespace(
            config=config_path,
            session_id="tied-session",
            format=out_format,
            output="",
            include_events=True,
        )
    )
    assert result == 0
    return capsys.readouterr().out


def _order(jsonl: str) -> list[str]:
    """Exported records in order: messages by body, events as `#<id>`."""
    records = [json.loads(line) for line in jsonl.splitlines()]
    return [
        record["body"] if record["type"] == "message" else f"#{record['id']}"
        for record in records
    ]


def _export_tied_transcript(tmp_path, capsys, *, message_ids: list[str]) -> list[str]:
    def write(sessions: SessionStore, session_id: str) -> None:
        with (
            _clock(TIED_AT),
            patch(
                MESSAGE_UUID,
                side_effect=[SimpleNamespace(hex=value) for value in message_ids],
            ),
        ):
            for index in range(len(message_ids)):
                sessions.append_message(
                    session_id=session_id, role="inbound", body=f"m{index}"
                )
                sessions.append_event(
                    session_id=session_id,
                    event_type="test.tied",
                    payload={"after": f"m{index}"},
                )
            for index in range(10):
                sessions.append_event(
                    session_id=session_id,
                    event_type="test.tied",
                    payload={"tail": index},
                )

    return _order(_export(_write_session(tmp_path, write), capsys))


@pytest.mark.parametrize(
    "message_ids",
    [
        # Each message id sorts before the id of the message appended before it.
        "fc80",
        # Each message id sorts after it.
        "08cf",
    ],
)
def test_transcript_keeps_tied_messages_in_append_order(
    tmp_path, capsys, message_ids
) -> None:
    order = _export_tied_transcript(
        tmp_path, capsys, message_ids=[char * 32 for char in message_ids]
    )

    # One created_at, whatever the message ids: the messages in append order,
    # then the 14 events in insertion order.
    assert order == [
        *(f"m{index}" for index in range(4)),
        *(f"#{event_id}" for event_id in range(1, 15)),
    ]


def test_transcript_keeps_insertion_order_of_tied_events(tmp_path, capsys) -> None:
    listed: list[str] = []

    def write(sessions: SessionStore, session_id: str) -> None:
        with _clock(TIED_AT):
            for index in range(12):
                sessions.append_event(
                    session_id=session_id,
                    event_type="test.tied",
                    payload={"append": index},
                )
        listed.extend(
            f"#{event.id}"
            for event in sessions.list_events(
                session_id=session_id, newest_first=False, limit=100
            )
        )

    config_path = _write_session(tmp_path, write)
    jsonl = _export(config_path, capsys)
    markdown = _export(config_path, capsys, out_format="md")

    assert listed == [f"#{event_id}" for event_id in range(1, 13)]
    assert _order(jsonl) == listed
    # Markdown shows no event ids; the payloads carry the append order.
    assert re.findall(r'"append": (\d+)', markdown) == [str(n) for n in range(12)]


def test_transcript_shows_tied_messages_before_tied_events(tmp_path, capsys) -> None:
    def write(sessions: SessionStore, session_id: str) -> None:
        def message(role: str, body: str) -> None:
            sessions.append_message(session_id=session_id, role=role, body=body)

        def event(event_type: str) -> None:
            sessions.append_event(
                session_id=session_id, event_type=event_type, payload={}
            )

        with patch(
            MESSAGE_UUID,
            side_effect=[SimpleNamespace(hex=char * 32) for char in "f0c"],
        ):
            with _clock("2026-10-22T01:00:00+00:00"):
                message("inbound", "earlier")
            # The clock steps back after this event.
            with _clock("2026-10-22T01:00:02+00:00"):
                event("clock.ahead")
            # A turn written within one clock tick.
            with _clock("2026-10-22T01:00:01+00:00"):
                for _ in range(7):
                    event("test.setup")
                event("run.running")
                message("inbound", "hello")
                event("run.responding")
                message("outbound", "reply")
                event("response.persisted")
                event("run.completed")

    config_path = _write_session(tmp_path, write)
    jsonl = _export(config_path, capsys)
    markdown = _export(config_path, capsys, out_format="md")

    # created_at first. At the tie, the messages in append order, then the
    # events in insertion order (ids 2-12, crossing 9/10).
    assert _order(jsonl) == [
        "earlier",
        "hello",
        "reply",
        *(f"#{event_id}" for event_id in range(2, 13)),
        "#1",
    ]
    assert re.findall(r"^### (.+)$", markdown, flags=re.MULTILINE) == [
        "Inbound",
        "Inbound",
        "Outbound",
        *["Event: test.setup"] * 7,
        "Event: run.running",
        "Event: run.responding",
        "Event: response.persisted",
        "Event: run.completed",
        "Event: clock.ahead",
    ]
    bodies = {"earlier", "hello", "reply"}
    assert [line for line in markdown.splitlines() if line in bodies] == [
        "earlier",
        "hello",
        "reply",
    ]
