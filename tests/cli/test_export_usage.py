from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from openminion.base.config import OpenMinionConfig, save_config
from openminion.cli.commands.export import run_export
from openminion.modules.storage import build_runtime_storage
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


def _export_tied_transcript(tmp_path, capsys, *, message_ids: list[str]) -> list[dict]:
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
        with (
            patch(MESSAGE_CLOCK, return_value=TIED_AT),
            patch(EVENT_CLOCK, return_value=TIED_AT),
            patch(
                MESSAGE_UUID,
                side_effect=[SimpleNamespace(hex=value) for value in message_ids],
            ),
        ):
            for index in range(len(message_ids)):
                storage.sessions.append_message(
                    session_id=session.id, role="inbound", body=f"m{index}"
                )
                storage.sessions.append_event(
                    session_id=session.id,
                    event_type="test.tied",
                    payload={"after": f"m{index}"},
                )
            for index in range(10):
                storage.sessions.append_event(
                    session_id=session.id,
                    event_type="test.tied",
                    payload={"tail": index},
                )
    finally:
        storage.close()

    result = run_export(
        SimpleNamespace(
            config=str(config_path),
            session_id="tied-session",
            format="jsonl",
            output="",
            include_events=True,
        )
    )
    assert result == 0
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_transcript_keeps_tied_messages_in_append_order(tmp_path, capsys) -> None:
    # Each message id sorts before the id of the message appended before it.
    records = _export_tied_transcript(
        tmp_path, capsys, message_ids=[char * 32 for char in "fc80"]
    )

    assert [item["body"] for item in records if item["type"] == "message"] == [
        "m0",
        "m1",
        "m2",
        "m3",
    ]
    events = [item for item in records if item["type"] == "event"]
    assert events == sorted(events, key=lambda item: (item["created_at"], item["id"]))
    assert len(events) == 14
    assert {item["created_at"] for item in records} == {TIED_AT}


def test_transcript_order_is_unchanged_when_messages_follow_id_order(
    tmp_path, capsys
) -> None:
    records = _export_tied_transcript(
        tmp_path, capsys, message_ids=[char * 32 for char in "08cf"]
    )

    # The (created_at, id) order every export has used, including tied events
    # whose ids compare as strings.
    assert records == sorted(records, key=lambda item: (item["created_at"], item["id"]))
    assert [item["body"] for item in records if item["type"] == "message"] == [
        "m0",
        "m1",
        "m2",
        "m3",
    ]
