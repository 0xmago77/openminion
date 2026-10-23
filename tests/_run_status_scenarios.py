"""Run-status scenarios shared by the SQLite and Postgres tests (#352).

Each scenario appends events to a runtime `SessionStore` and compares the
readers in `openminion.modules.task.run` with a plain event-by-event
reduction over all of the session's events, which is their contract.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

from openminion.modules.storage.runtime.session_store import EventRecord, SessionStore
from openminion.modules.task.run import (
    ATTACH_ROLE_WRITER,
    DELIVERY_STATE_ACKED,
    DELIVERY_STATE_DELIVERED,
    DELIVERY_STATE_NONE,
    DELIVERY_STATE_PERSISTED,
    RUN_STATE_CANCELLED,
    RUN_STATE_COMPLETED,
    RUN_STATE_FAILED,
    RUN_STATE_QUEUED,
    RUN_STATE_RESPONDING,
    RUN_STATE_RUNNING,
    RUN_STATE_WAITING_TOOL,
    list_session_run_events,
    list_session_runs,
    resolve_thread_lifecycle,
)

EVENT_CLOCK = "openminion.modules.storage.runtime.session_store.lifecycle.utc_now_iso"
RUN_STATES = {
    RUN_STATE_QUEUED,
    RUN_STATE_RUNNING,
    RUN_STATE_WAITING_TOOL,
    RUN_STATE_RESPONDING,
    RUN_STATE_COMPLETED,
    RUN_STATE_FAILED,
    RUN_STATE_CANCELLED,
}
TERMINAL_STATES = {RUN_STATE_COMPLETED, RUN_STATE_FAILED, RUN_STATE_CANCELLED}
# Run ids that need JSON escaping, or that `LIKE` would treat as wildcards.
SPECIAL_RUN_IDS = ('q"uote', "back\\slash", "café", "per%cent", "under_score")


@contextmanager
def stepping_clock() -> Iterator[list[str]]:
    """Patch the event clock: 1 s forward per append, 7 s back every 5th."""
    base = datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)
    stamps: list[str] = []

    def tick(counter=itertools.count()) -> str:
        index = next(counter)
        offset = index - 8 * (index // 5)
        stamps.append((base + timedelta(seconds=offset, microseconds=1)).isoformat())
        return stamps[-1]

    with patch(EVENT_CLOCK, side_effect=tick):
        yield stamps


def append_runs(sessions: SessionStore, session_id: str) -> None:
    """Interleaved runs whose events cover every run-status fact."""

    def run(event_type: str, run_id: str, **payload: Any) -> None:
        sessions.append_event(
            session_id=session_id,
            event_type=event_type,
            payload={"run_id": run_id, **payload},
        )

    specials = itertools.cycle(SPECIAL_RUN_IDS)
    for index in range(6):
        long_run = "long"
        short = f"short-{index}"
        special = next(specials)
        run("run.queued", short, state="queued", step="turn.accepted")
        run("run.running", long_run, state="running", step=f"step-{index}")
        run("run.queued", special, state="queued", step="turn.accepted")
        run("run.waiting_tool", short, state="waiting_tool", step="", error=None)
        # A nested reference to another run, and a letter-case variant.
        run("run.running", f"nested-{index}", parent={"run_id": short})
        run("run.running", short.upper(), state="running")
        run("run.failed", special, state="failed", step="turn.failed", error=503)
        # The payload state decides over the event type when it is a run state.
        run("run.queued", short, state="completed", step="  ", error="  ")
        run("run.completed", f"suffix-{index}", state="bogus")
        run("run.failed", f"padded-{index}", state=" RUNNING ")
        run("run.cancel_requested", long_run)
        if index % 2:
            run("run.completed", long_run, state="completed", error="boom")
        sessions.append_event(
            session_id=session_id, event_type="tool.call", payload={"run_id": short}
        )


def _state(event: EventRecord) -> str:
    candidate = str(event.payload.get("state") or "").strip().lower()
    if candidate in RUN_STATES:
        return candidate
    suffix = event.event_type.split(".", 1)[1].strip().lower()
    return suffix if suffix in RUN_STATES else RUN_STATE_RUNNING


def _all_events(sessions: SessionStore, session_id: str) -> list[EventRecord]:
    return sessions.list_events(session_id=session_id, limit=1_000_000)


def expected_runs(
    sessions: SessionStore, session_id: str, *, limit: int, scan_limit: int
) -> list[dict[str, Any]]:
    run_events = [
        event
        for event in _all_events(sessions, session_id)
        if event.event_type.startswith("run.")
    ]
    window = run_events[-max(limit, scan_limit) :]
    listed = {str(event.payload.get("run_id", "")) for event in window} - {""}
    runs: dict[str, dict[str, Any]] = {}
    for event in run_events:
        run_id = str(event.payload.get("run_id", ""))
        if run_id not in listed:
            continue
        run = runs.setdefault(
            run_id,
            {
                "run_id": run_id,
                "started_at": event.created_at,
                "ended_at": "",
                "current_step": "",
                "error": "",
                "event_count": 0,
            },
        )
        run["event_count"] += 1
        run["state"] = _state(event)
        step = str(event.payload.get("step") or "").strip()
        error = event.payload.get("error")
        if step:
            run["current_step"] = step
        if error is not None and str(error).strip():
            run["error"] = str(error).strip()
        if run["state"] in TERMINAL_STATES:
            run["ended_at"] = event.created_at
    ordered = sorted(
        runs.values(), key=lambda run: (run["started_at"], run["run_id"]), reverse=True
    )
    return ordered[: max(1, min(limit, 500))]


def check_run_readers(sessions: SessionStore, session_id: str) -> None:
    run_count = len(
        sessions.list_events(
            session_id=session_id, limit=10_000, event_type_prefix="run."
        )
    )
    for scan_limit in (1, 2, 5, 13, 40, run_count - 1, run_count, 2000):
        for limit in (1, 3, 20):
            expected = expected_runs(
                sessions, session_id, limit=limit, scan_limit=scan_limit
            )
            listed = [
                {key: getattr(run, key) for key in expected[0]}
                for run in list_session_runs(
                    sessions, session_id=session_id, limit=limit, scan_limit=scan_limit
                )
            ]
            assert listed == expected, (scan_limit, limit)
    every_event = _all_events(sessions, session_id)
    run_ids = {str(event.payload.get("run_id", "")) for event in every_event} - {""}
    for run_id in sorted(run_ids):
        own = [
            event.id
            for event in every_event
            if event.event_type.startswith("run.")
            and event.payload.get("run_id") == run_id
        ]
        for limit in (1, 2, 1000):
            listed_ids = [
                event.id
                for event in list_session_run_events(
                    sessions, session_id=session_id, run_id=run_id, limit=limit
                )
            ]
            assert listed_ids == own[-limit:], (run_id, limit)


def append_threads(sessions: SessionStore, session_id: str) -> None:
    """Interleaved threads; `quiet` starts first and is untouched for a while."""

    def event(event_type: str, thread_id: str | None, **payload: Any) -> None:
        if thread_id is not None:
            payload = {"conversation_id": "conv", "thread_id": thread_id, **payload}
        sessions.append_event(
            session_id=session_id, event_type=event_type, payload=payload
        )

    event("run.queued", "quiet", run_id="q1", state="queued", invocation_id="inv-q1")
    event("client.attach", "quiet", attach_id="writer-q", attach_role="writer")
    event("client.attach", "quiet", attach_id="observer-q", attach_role="observer")
    event("run.completed", "quiet", run_id="q1", state="completed")
    event("response.persisted", "quiet", run_id="q1")
    for index in range(12):
        run_id = f"b{index}"
        event("run.queued", "busy", run_id=run_id, invocation_id=f"inv-b{index}")
        event("run.queued", "busy", run_id=f"{run_id}-retry")
        event("client.attach", "busy", attach_id=f"attach-{index}", attach_role="")
        event("run.running", "busy", run_id=run_id, state="running")
        if index % 4 == 0:
            # No thread or conversation: it belongs to every thread of `conv`
            # only when the conversation is the session itself.
            event("session.note", None, note=index)
        event("run.completed", "busy", run_id=run_id, state="completed")
    event("run.cancel_requested", "busy", run_id="b11")
    event("client.detached", "busy", attach_id="attach-11")
    event("response.delivered", "quiet", run_id="q1")


def expected_thread(
    sessions: SessionStore, session_id: str, *, conversation_id: str, thread_id: str
) -> dict[str, Any]:
    def matches(event: EventRecord) -> bool:
        conversation = str(event.payload.get("conversation_id") or "").strip()
        thread = str(event.payload.get("thread_id") or "").strip()
        if conversation_id and conversation != conversation_id:
            if conversation or conversation_id != session_id:
                return False
        return not (thread_id and thread and thread != thread_id)

    events = [e for e in _all_events(sessions, session_id) if matches(e)]
    runs = [
        e
        for e in events
        if e.event_type.startswith("run.") and str(e.payload.get("run_id") or "")
    ]
    starts = [
        e
        for e in events
        if e.event_type == "run.queued" and str(e.payload.get("invocation_id") or "")
    ]
    writers = [
        e
        for e in events
        if e.event_type == "client.attach"
        and str(e.payload.get("attach_id") or "").strip()
        and str(e.payload.get("attach_role") or "").strip().lower()
        in {"", ATTACH_ROLE_WRITER}
    ]
    types = {e.event_type for e in events}
    delivery = DELIVERY_STATE_NONE
    for event_type, state in (
        ("response.persisted", DELIVERY_STATE_PERSISTED),
        ("response.delivered", DELIVERY_STATE_DELIVERED),
        ("response.acked", DELIVERY_STATE_ACKED),
    ):
        if event_type in types:
            delivery = state
    return {
        "latest_run_id": runs[-1].payload["run_id"] if runs else "",
        "latest_run_state": _state(runs[-1]) if runs else "",
        "invocation_id": starts[-1].payload["invocation_id"] if starts else "",
        "invocation_source_event_id": starts[-1].id if starts else 0,
        "latest_event_id": events[-1].id if events else 0,
        "updated_at": events[-1].created_at if events else "",
        "delivery_state": delivery,
        "writer_attach_id": writers[-1].payload["attach_id"] if writers else "",
    }


def check_thread_projection(sessions: SessionStore, session_id: str) -> None:
    for conversation_id, thread_id in (
        ("conv", "quiet"),
        ("conv", "busy"),
        ("conv", "missing"),
        (session_id, "busy"),
        ("", "quiet"),
    ):
        projection = resolve_thread_lifecycle(
            sessions,
            session_id=session_id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        expected = expected_thread(
            sessions,
            session_id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        assert {key: getattr(projection, key) for key in expected} == expected, (
            conversation_id,
            thread_id,
        )
