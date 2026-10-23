import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openminion.modules.storage.runtime.migrations import migrate_database
from openminion.modules.storage.runtime.session_store import SessionStore
from openminion.modules.storage.runtime.sqlite import connect_database
from openminion.services.runtime.run_status import (
    RUN_STATE_COMPLETED,
    RUN_STATE_FAILED,
    RUN_STATE_QUEUED,
    RUN_STATE_RUNNING,
    THREAD_STATE_AWAITING,
    THREAD_STATE_RESPONSE_UNDELIVERED,
    THREAD_STATE_SETTLED,
    THREAD_STATE_DETACHED,
    DELIVERY_STATE_ACKED,
    ATTACH_ROLE_OBSERVER,
    ATTACH_ROLE_WRITER,
    resolve_thread_lifecycle,
    append_run_state_event,
    resolve_thread_routing_decision,
    THREAD_DECISION_REPLAY,
    THREAD_DECISION_FORK,
    THREAD_DECISION_RESUME,
)

EVENT_CLOCK = "openminion.modules.storage.runtime.session_store.lifecycle.utc_now_iso"


class ConversationLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.database_path = Path(self._tmp.name) / "state" / "openminion.db"
        migrate_database(self.database_path)
        self.connection = connect_database(self.database_path)
        self.sessions = SessionStore(self.connection)
        self.session = self.sessions.resolve_session(
            agent_id="main",
            channel="console",
            target="conversation-lifecycle",
        )

    def tearDown(self) -> None:
        self.connection.close()
        self._tmp.cleanup()

    def test_completed_with_outbound_is_settled(self) -> None:
        conversation_id = "conv-1"
        thread_id = "thread-1"
        run_id = "run-1"
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="inbound",
            body="hello",
        )
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_RUNNING,
            current_step="agent.generate",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="outbound",
            body="world",
        )
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="response.delivered",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )

        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_SETTLED)

    def test_completed_without_outbound_is_undelivered(self) -> None:
        conversation_id = "conv-2"
        thread_id = "thread-2"
        run_id = "run-2"
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="inbound",
            body="hi",
        )
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )

        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_RESPONSE_UNDELIVERED)
        self.assertEqual(projection.pending_response_id, run_id)

    def test_running_is_awaiting(self) -> None:
        conversation_id = "conv-3"
        thread_id = "thread-3"
        run_id = "run-3"
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_RUNNING,
            current_step="agent.generate",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_AWAITING)

    def test_detached_without_run_marks_detached(self) -> None:
        conversation_id = "conv-4"
        thread_id = "thread-4"
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="client.detached",
            payload={
                "conversation_id": conversation_id,
                "thread_id": thread_id,
                "attach_id": "att-1",
            },
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_DETACHED)

    def test_writer_attach_role_ignores_observer(self) -> None:
        conversation_id = "conv-5"
        thread_id = "thread-5"
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="client.attach",
            payload={
                "conversation_id": conversation_id,
                "thread_id": thread_id,
                "attach_id": "att-writer",
                "attach_role": ATTACH_ROLE_WRITER,
            },
        )
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="client.attach",
            payload={
                "conversation_id": conversation_id,
                "thread_id": thread_id,
                "attach_id": "att-observer",
                "attach_role": ATTACH_ROLE_OBSERVER,
            },
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.writer_attach_id, "att-writer")

    def test_delivery_state_ack_trumps_delivery(self) -> None:
        conversation_id = "conv-6"
        thread_id = "thread-6"
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="response.persisted",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="response.delivered",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="response.acked",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.delivery_state, DELIVERY_STATE_ACKED)

    def test_cancel_requested_qualifier_on_undelivered_completion(self) -> None:
        conversation_id = "conv-7"
        thread_id = "thread-7"
        run_id = "run-7"
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="run.cancel_requested",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="outbound",
            body="pending",
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_RESPONSE_UNDELIVERED)
        self.assertEqual(projection.qualifier, "cancel_requested")

    def test_detached_qualifier_on_undelivered_completion(self) -> None:
        conversation_id = "conv-8"
        thread_id = "thread-8"
        run_id = "run-8"
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="client.detached",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="outbound",
            body="pending",
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_RESPONSE_UNDELIVERED)
        self.assertEqual(projection.qualifier, "detached_before_delivery")

    def test_routing_decision_prefers_replay_for_undelivered(self) -> None:
        conversation_id = "conv-replay"
        thread_id = "thread-replay"
        run_id = "run-replay"
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="outbound",
            body="pending",
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        decision = resolve_thread_routing_decision(
            lifecycle=projection,
            session_id=self.session.id,
            conversation_id=conversation_id,
            requested_thread_id=thread_id,
            attach_id="att-1",
            resume_requested=False,
            reset_requested=False,
            explicit_thread=False,
            auto_resume_inferred=False,
        )
        self.assertEqual(decision.action, THREAD_DECISION_REPLAY)
        self.assertEqual(decision.reason_code, "undelivered_response_pending")
        self.assertTrue(decision.should_replay_pending)

    def test_routing_decision_forks_settled_without_resume(self) -> None:
        conversation_id = "conv-fork"
        thread_id = "thread-fork"
        run_id = "run-fork"
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="outbound",
            body="done",
        )
        self.sessions.append_event(
            session_id=self.session.id,
            event_type="response.acked",
            payload={"conversation_id": conversation_id, "thread_id": thread_id},
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        decision = resolve_thread_routing_decision(
            lifecycle=projection,
            session_id=self.session.id,
            conversation_id=conversation_id,
            requested_thread_id="",
            attach_id="",
            resume_requested=False,
            reset_requested=False,
            explicit_thread=False,
            auto_resume_inferred=False,
        )
        self.assertEqual(decision.action, THREAD_DECISION_FORK)
        self.assertEqual(decision.reason_code, "settled_without_resume")
        self.assertIn(conversation_id, decision.thread_id)

    def test_routing_decision_resumes_for_explicit_thread(self) -> None:
        conversation_id = "conv-resume"
        thread_id = "thread-resume"
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id="run-resume",
            state=RUN_STATE_RUNNING,
            current_step="agent.generate",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        decision = resolve_thread_routing_decision(
            lifecycle=projection,
            session_id=self.session.id,
            conversation_id=conversation_id,
            requested_thread_id=thread_id,
            attach_id="att-explicit",
            resume_requested=True,
            reset_requested=False,
            explicit_thread=True,
            auto_resume_inferred=False,
        )
        self.assertEqual(decision.action, THREAD_DECISION_RESUME)
        self.assertEqual(decision.reason_code, "explicit_thread_requested")
        self.assertEqual(decision.thread_id, thread_id)

    def test_internal_error_outbound_is_settled_not_undelivered(self) -> None:
        conversation_id = "conv-error"
        thread_id = "thread-error"
        run_id = "run-error"
        append_run_state_event(
            self.sessions,
            session_id=self.session.id,
            run_id=run_id,
            state=RUN_STATE_COMPLETED,
            current_step="turn.completed",
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.sessions.append_message(
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
            role="outbound",
            body=(
                "General act work ended without the required typed "
                "finalization_status contract."
            ),
            metadata={"brain_status": "error", "finish_reason": "error"},
        )

        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )
        self.assertEqual(projection.thread_state, THREAD_STATE_SETTLED)
        self.assertEqual(projection.qualifier, "internal_error_outbound")
        self.assertEqual(projection.pending_response_id, "")

    def test_projection_follows_insertion_order_when_clock_steps_back(self) -> None:
        conversation_id = "conv-clock"
        thread_id = "thread-clock"
        # The wall clock steps back ~1.3 s before the second invocation starts.
        stamps = [
            "2026-10-21T17:17:00.300000+00:00",
            "2026-10-21T17:17:00.400000+00:00",
            "2026-10-21T17:16:59.100000+00:00",
            "2026-10-21T17:16:59.200000+00:00",
        ]
        appends = (
            ("run-1", RUN_STATE_QUEUED, "turn.accepted"),
            ("run-1", RUN_STATE_FAILED, "turn.failed"),
            ("run-2", RUN_STATE_QUEUED, "turn.accepted"),
            ("run-2", RUN_STATE_RUNNING, "agent.generate"),
        )
        with patch(EVENT_CLOCK, side_effect=stamps):
            events = [
                append_run_state_event(
                    self.sessions,
                    session_id=self.session.id,
                    run_id=run_id,
                    state=state,
                    current_step=step,
                    conversation_id=conversation_id,
                    thread_id=thread_id,
                    payload=(
                        {"invocation_id": f"invocation-{run_id}"}
                        if state == RUN_STATE_QUEUED
                        else None
                    ),
                )
                for run_id, state, step in appends
            ]

        projection = resolve_thread_lifecycle(
            self.sessions,
            session_id=self.session.id,
            conversation_id=conversation_id,
            thread_id=thread_id,
        )

        second_start, second_running = events[2], events[3]
        self.assertEqual(projection.latest_run_id, "run-2")
        self.assertEqual(projection.latest_run_state, RUN_STATE_RUNNING)
        self.assertEqual(projection.thread_state, THREAD_STATE_AWAITING)
        self.assertEqual(projection.invocation_id, "invocation-run-2")
        self.assertEqual(projection.invocation_source_event_id, second_start.id)
        self.assertEqual(projection.latest_event_id, second_running.id)
        self.assertEqual(projection.updated_at, second_running.created_at)
