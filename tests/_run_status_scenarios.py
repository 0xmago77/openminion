"""Run-status scenarios shared by the SQLite and Postgres tests (#352).

Each scenario appends events to a runtime `SessionStore` and compares the
readers in `openminion.modules.task.run` with a plain event-by-event
reduction over all of the session's events, which is their contract. The
reduction reads each event with the readers' own Python normalization
(`_to_run_event`, `_extract_event_error`, `_event_matches_thread`), so the
SQL that selects events must agree with it on every payload.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator
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
    append_run_state_event,
    list_session_run_events,
    list_session_runs,
    resolve_thread_lifecycle,
)
from openminion.modules.task.run.status import (
    _event_matches_thread,
    _extract_event_error,
    _to_run_event,
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
# Every character `str.strip()` removes; SQL `TRIM` without a set removes spaces only.
PADDING = "".join(chr(code) for code in range(0x3001) if chr(code).isspace())


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


def append_payload_variants(sessions: SessionStore, session_id: str) -> None:
    """Run events with payload values the readers normalize in Python.

    `append_run_state_event(payload=...)` stores these as given: text padded
    with any whitespace `str.strip()` removes, JSON null, booleans, numbers, an
    empty object or array, NaN, Infinity and NUL. A `RUN.` event type is listed
    by SQLite `LIKE` but gets no state from its suffix.
    """

    def run(event_state: str, run_id: Any, /, **payload: Any) -> None:
        append_run_state_event(
            sessions,
            session_id=session_id,
            run_id="replaced",
            state=event_state,
            current_step="",
            payload={"run_id": run_id, **payload},
        )

    run("queued", "r", step="first", error="earlier error")
    run("running", f"{PADDING}r{PADDING}", step=PADDING, error=PADDING)
    run("failed", "r", state=f"{PADDING}RUNNING{PADDING}")
    # A zero-width space is not whitespace to `str.strip()`.
    run("queued", "\u200br")
    run("queued", 7, step=0, error=0)
    run("running", "7", step=False, error=False)
    run("completed", f"{PADDING}7", step=None, error=None)
    run("queued", None)
    run("queued", True, state=None)
    run("failed", {}, state=5)
    run("queued", [], error={})
    run("queued", "", error="no run")
    run("queued", PADDING, error="no run")
    # NaN and Infinity are not JSON, and Postgres cannot return a NUL as text.
    run("running", "r", step=float("nan"), latency=float("inf"))
    run("running", "r", error=f"bad{chr(0)}byte", output=[float("-inf"), chr(0)])
    sessions.append_event(
        session_id=session_id,
        event_type="RUN.failed",
        payload={"run_id": "r", "state": "bogus"},
    )


def _all_events(sessions: SessionStore, session_id: str) -> list[EventRecord]:
    return sessions.list_events(session_id=session_id, limit=1_000_000)


def _run_events(sessions: SessionStore, session_id: str) -> list[EventRecord]:
    """The session's `run.` events, selected by the store as the readers select them."""
    return sessions.list_events(
        session_id=session_id, limit=1_000_000, event_type_prefix="run."
    )


def expected_runs(
    sessions: SessionStore, session_id: str, *, limit: int, scan_limit: int
) -> list[dict[str, Any]]:
    run_events = _run_events(sessions, session_id)
    window = run_events[-max(limit, scan_limit) :]
    listed = {item.run_id for item in map(_to_run_event, window) if item is not None}
    runs: dict[str, dict[str, Any]] = {}
    for event in run_events:
        item = _to_run_event(event)
        if item is None or item.run_id not in listed:
            continue
        run = runs.setdefault(
            item.run_id,
            {
                "run_id": item.run_id,
                "started_at": event.created_at,
                "ended_at": "",
                "current_step": "",
                "error": "",
                "event_count": 0,
            },
        )
        run["event_count"] += 1
        run["state"] = item.state
        error = _extract_event_error(item.payload)
        if item.current_step:
            run["current_step"] = item.current_step
        if error:
            run["error"] = error
        if item.state in TERMINAL_STATES:
            run["ended_at"] = event.created_at
    ordered = sorted(
        runs.values(), key=lambda run: (run["started_at"], run["run_id"]), reverse=True
    )
    return ordered[: max(1, min(limit, 500))]


def check_run_readers(sessions: SessionStore, session_id: str) -> None:
    run_events = _run_events(sessions, session_id)
    run_count = len(run_events)
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
    items = [item for item in map(_to_run_event, run_events) if item is not None]
    for run_id in sorted({item.run_id for item in items}):
        own = [item.id for item in items if item.run_id == run_id]
        for limit in (1, 2, 1000):
            for requested in (run_id, f" {run_id}\t"):
                listed_ids = [
                    event.id
                    for event in list_session_run_events(
                        sessions, session_id=session_id, run_id=requested, limit=limit
                    )
                ]
                assert listed_ids == own[-limit:], (requested, limit)


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


def append_thread_payload_variants(sessions: SessionStore, session_id: str) -> None:
    """Thread events with payload values the readers normalize in Python."""

    def event(event_type: str, **payload: Any) -> None:
        sessions.append_event(
            session_id=session_id, event_type=event_type, payload=payload
        )

    padded = {"conversation_id": f"{PADDING}conv{PADDING}", "thread_id": "\nt\t"}
    event("run.queued", **padded, run_id="t1", invocation_id=f"{PADDING}inv-1")
    event("client.attach", **padded, attach_id=f"{PADDING}w1", attach_role=" WRITER\t")
    # JSON null reads as "None": an attach id, an invocation id, and a role
    # that is not the writer's.
    event("client.attach", conversation_id="conv", thread_id="t", attach_id=None)
    event(
        "client.attach",
        conversation_id="conv",
        thread_id="t",
        attach_id="o1",
        attach_role=None,
    )
    event(
        "run.queued",
        conversation_id="conv",
        thread_id="t",
        run_id="t2",
        invocation_id=None,
    )
    # Not a run event for the thread, although SQLite `LIKE 'run.%'` matches it.
    event("RUN.running", conversation_id="conv", thread_id="t", run_id="t3")
    # False, 0 and null ids are empty: in every thread of the session's conversation.
    event(
        "run.running", conversation_id=False, thread_id=0, run_id="t4", state="running"
    )
    event("run.waiting_tool", conversation_id=None, thread_id=None, run_id="t5")
    # Any event of the session is read: one Postgres could not parse or return.
    event(
        "tool.result", conversation_id="conv", thread_id="t", output=f"bin{chr(0)}ary"
    )
    event("tool.metrics", conversation_id="conv", thread_id="t", score=float("nan"))
    # A zero-width space is not whitespace: another thread.
    event("run.queued", conversation_id="conv", thread_id="\u200bt", run_id="zw")
    event("run.failed", **padded, run_id=f"{PADDING}t1{PADDING}", state="\tfailed\n")


def check_thread_payload_variants(sessions: SessionStore, session_id: str) -> None:
    for conversation_id, thread_id in (
        ("conv", "t"),
        (session_id, "t"),
        ("conv", "\u200bt"),
        ("", "t"),
        (f" conv{PADDING}", f"{PADDING}t"),
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


def check_review_cases(
    sessions: SessionStore, new_session: Callable[[str], str]
) -> None:
    """The four cases of the #372 review, each in a session of its own."""

    def append(session_id: str, state: str, **kwargs: Any) -> EventRecord:
        return append_run_state_event(
            sessions,
            session_id=session_id,
            run_id="r",
            state=state,
            current_step="",
            **kwargs,
        )

    session_id = new_session("padded-run-id")
    append(session_id, "queued")
    append(session_id, "running", payload={"run_id": " r "})
    runs = list_session_runs(sessions, session_id=session_id)
    assert [(run.run_id, run.event_count) for run in runs] == [("r", 2)]
    assert (
        len(list_session_run_events(sessions, session_id=session_id, run_id="r")) == 2
    )

    session_id = new_session("blank-error")
    append(session_id, "queued", payload={"error": "earlier error"})
    append(session_id, "running", payload={"error": "\n\t"})
    assert (
        list_session_runs(sessions, session_id=session_id)[0].error == "earlier error"
    )

    session_id = new_session("padded-state")
    append(session_id, "queued")
    append(session_id, "failed", payload={"state": "\trunning\n"})
    run = list_session_runs(sessions, session_id=session_id)[0]
    assert (run.state, run.ended_at) == (RUN_STATE_RUNNING, "")

    session_id = new_session("padded-thread")
    ids = {"conversation_id": "conv", "thread_id": "t"}
    append(session_id, "queued", **ids)
    failed = append(
        session_id,
        "failed",
        **ids,
        payload={"conversation_id": "\tconv\n", "thread_id": "\nt\t"},
    )
    projection = resolve_thread_lifecycle(sessions, session_id=session_id, **ids)
    assert (projection.latest_run_state, projection.latest_event_id) == (
        RUN_STATE_FAILED,
        failed.id,
    )


def expected_thread(
    sessions: SessionStore, session_id: str, *, conversation_id: str, thread_id: str
) -> dict[str, Any]:
    conversation_value = str(conversation_id or "").strip()
    thread_value = str(thread_id or "").strip()
    events = [
        e
        for e in _all_events(sessions, session_id)
        if _event_matches_thread(
            e,
            conversation_id=conversation_value,
            thread_id=thread_value,
            session_id=session_id,
        )
    ]
    runs = [
        item
        for item in (
            _to_run_event(e) for e in events if e.event_type.startswith("run.")
        )
        if item is not None
    ]

    def text(event: EventRecord, key: str) -> str:
        return str(event.payload.get(key, "")).strip()

    starts = [
        e for e in events if e.event_type == "run.queued" and text(e, "invocation_id")
    ]
    writers = [
        text(e, "attach_id")
        for e in events
        if e.event_type == "client.attach"
        and text(e, "attach_id")
        and text(e, "attach_role").lower() in {"", ATTACH_ROLE_WRITER}
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
        "latest_run_id": runs[-1].run_id if runs else "",
        "latest_run_state": runs[-1].state if runs else "",
        "invocation_id": text(starts[-1], "invocation_id") if starts else "",
        "invocation_source_event_id": starts[-1].id if starts else 0,
        "latest_event_id": events[-1].id if events else 0,
        "updated_at": events[-1].created_at if events else "",
        "delivery_state": delivery,
        "writer_attach_id": writers[-1] if writers else "",
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
