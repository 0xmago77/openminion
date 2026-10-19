from types import SimpleNamespace

import pytest


class _SnapshotStore:
    def __init__(
        self,
        *,
        fail_list_call: int | None = None,
        fail_candidates: bool = False,
        fail_vector_probe: bool = False,
    ) -> None:
        self.fail_list_call = fail_list_call
        self.fail_candidates = fail_candidates
        self.fail_vector_probe = fail_vector_probe
        self.list_calls: list[list[str]] = []
        self.candidate_options = None

    @property
    def _vector_adapter(self):  # noqa: ANN202, SLF001
        if self.fail_vector_probe:
            raise RuntimeError("secret-vector-token")
        return object()

    def list(self, options):  # noqa: ANN001, ANN201
        self.list_calls.append(options.scopes)
        if self.fail_list_call == len(self.list_calls):
            raise RuntimeError("secret-record-token")
        if len(options.scopes) == 2:
            return [SimpleNamespace(title="recent memory")]
        return {
            "session:test-session": [object(), object()],
            "agent:test-agent": [object()],
            "global": [object()],
        }.get(options.scopes[0], [])

    def candidate_list(self, options):  # noqa: ANN001, ANN201
        self.candidate_options = options
        if self.fail_candidates:
            raise RuntimeError("secret-candidate-token")
        return (
            [object()] if options.session_id == "test-session" else [object(), object()]
        )


class TestMemoryIntrospectionIntentDetector:
    CANONICAL_PROMPTS = [
        "what do you remember",
        "what do you recall",
        "what have you learned",
        "what have you stored",
        "what is in your memory",
        "show me what you remember",
        "summarize your memory",
        "summarize what you remember",
        "how much memory",
        "how much do you remember",
        "memory status",
        "recall memory",
        "show memory",
        "memory summary",
        "what did we discuss",
        "what have we talked about",
        "what do you know about me",
        "what do you know about this session",
        "tell me what you remember",
        "what facts do you have",
        "what information do you have stored",
    ]

    NON_INTROSPECTION_PROMPTS = [
        "what is the weather in Tokyo",
        "remember to call mom",
        "save this file",
        "what do you think about AI",
        "how are you doing",
        "tell me a joke",
        "what is 2+2",
        "hello",
        "help",
        "list tools",
    ]

    def test_introspection_patterns_exist(self) -> None:
        patterns = self.CANONICAL_PROMPTS
        assert len(patterns) > 0
        assert "what do you remember" in patterns


class TestMemoryRuntimeSnapshot:
    def test_memory_runtime_snapshot_schema(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            MemoryRuntimeSnapshot,
        )

        snapshot = MemoryRuntimeSnapshot(
            session_records=5,
            agent_records=3,
            global_records=10,
            candidate_count=2,
            total_records=18,
            memory_available=True,
            vector_search_available=True,
            degraded=False,
            recent_highlights=["Test memory 1", "Test memory 2"],
            snapshot_timestamp="2025-01-15T10:30:00Z",
            scope_filter="session:test-session",
        )

        assert snapshot.session_records == 5
        assert snapshot.total_records == 18
        assert snapshot.memory_available is True
        assert len(snapshot.recent_highlights) == 2

    def test_build_memory_snapshot_with_none_store(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_memory_snapshot,
        )

        snapshot = build_memory_snapshot(
            store=None,
            session_id="test-session",
            agent_id="test-agent",
        )

        assert snapshot.degraded is True
        assert snapshot.degraded_reason == "memory_store_unavailable"
        assert snapshot.memory_available is False

    def test_build_memory_snapshot_publishes_successful_bounded_reads(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_memory_snapshot,
        )

        store = _SnapshotStore()
        snapshot = build_memory_snapshot(
            store=store,
            session_id="test-session",
            agent_id="test-agent",
        )

        assert snapshot.memory_available is True
        assert snapshot.degraded is False
        assert snapshot.session_records == 2
        assert snapshot.agent_records == 1
        assert snapshot.global_records == 1
        assert snapshot.total_records == 4
        assert snapshot.candidate_count == 1
        assert snapshot.vector_search_available is True
        assert snapshot.recent_highlights == ["recent memory"]
        assert store.candidate_options.session_id == "test-session"
        assert store.list_calls[:3] == [
            ["session:test-session"],
            ["agent:test-agent"],
            ["global"],
        ]

    @pytest.mark.parametrize(
        ("fail_list_call", "fail_candidates", "fail_vector_probe"),
        [
            (1, False, False),
            (2, False, False),
            (3, False, False),
            (None, True, False),
            (None, False, True),
        ],
    )
    def test_build_memory_snapshot_required_failure_is_content_free(
        self,
        fail_list_call: int | None,
        fail_candidates: bool,
        fail_vector_probe: bool,
    ) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_memory_snapshot,
        )

        snapshot = build_memory_snapshot(
            store=_SnapshotStore(
                fail_list_call=fail_list_call,
                fail_candidates=fail_candidates,
                fail_vector_probe=fail_vector_probe,
            ),
            session_id="test-session",
            agent_id="test-agent",
        )

        assert snapshot.memory_available is False
        assert snapshot.degraded is True
        assert snapshot.degraded_reason == "memory_snapshot_query_failed"
        assert snapshot.session_records == 0
        assert snapshot.agent_records == 0
        assert snapshot.global_records == 0
        assert snapshot.total_records == 0
        assert snapshot.candidate_count == 0
        assert "secret" not in snapshot.model_dump_json()

    def test_build_memory_snapshot_keeps_highlights_optional(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_memory_snapshot,
        )

        snapshot = build_memory_snapshot(
            store=_SnapshotStore(fail_list_call=4),
            session_id="test-session",
            agent_id="test-agent",
        )

        assert snapshot.memory_available is True
        assert snapshot.degraded is False
        assert snapshot.total_records == 4
        assert snapshot.candidate_count == 1
        assert snapshot.recent_highlights == []

    def test_brain_adapter_returns_local_snapshot_schema(self) -> None:
        from openminion.modules.brain.adapters.memory import MemctlAdapter
        from openminion.modules.memory.storage.memory import InMemoryMemoryStore

        snapshot = MemctlAdapter(
            InMemoryMemoryStore(), agent_id="test-agent"
        ).get_runtime_snapshot(
            session_id="test-session",
            agent_id="test-agent",
        )

        assert snapshot["memory_available"] is True
        assert snapshot["candidate_count"] == 0
        assert snapshot["scope_filter"] == "session:test-session"


class TestRetrievalStatsSnapshot:
    def test_retrieval_stats_snapshot_schema(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            RetrievalStatsSnapshot,
        )

        snapshot = RetrievalStatsSnapshot(
            last_strategy="semantic",
            last_hit_count=5,
            last_query="test query",
            last_latency_ms=150.5,
            retrieve_available=True,
            total_retrievals_session=10,
            avg_hits_per_query=4.5,
            snapshot_timestamp="2025-01-15T10:30:00Z",
        )

        assert snapshot.last_strategy == "semantic"
        assert snapshot.last_hit_count == 5
        assert snapshot.retrieve_available is True

    def test_build_retrieval_stats_with_none_service(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_retrieval_stats,
        )

        snapshot = build_retrieval_stats(
            retrieve_svc=None,
            session_id="test-session",
        )

        assert snapshot.retrieve_available is False

    def test_build_retrieval_stats_keeps_recorded_errors_content_free(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_retrieval_stats,
        )

        snapshot = build_retrieval_stats(
            retrieve_svc=SimpleNamespace(
                _last_strategy="semantic",
                _last_hit_count=3,
                _last_query="project status",
                _last_latency_ms=12.5,
                _error_count=1,
                _last_error="secret-provider-token",
                _session_stats={
                    "test-session": {"count": 2, "total_hits": 3},
                },
            ),
            session_id="test-session",
        )

        assert snapshot.retrieve_available is True
        assert snapshot.last_strategy == "semantic"
        assert snapshot.last_hit_count == 3
        assert snapshot.total_retrievals_session == 2
        assert snapshot.avg_hits_per_query == 1.5
        assert snapshot.last_error == "retrieval_error_recorded"
        assert "secret" not in snapshot.model_dump_json()

    def test_build_retrieval_stats_failure_is_atomic_and_content_free(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            build_retrieval_stats,
        )

        class _FailingStats:
            _last_strategy = "semantic"

            @property
            def _last_hit_count(self) -> int:
                raise RuntimeError("secret-stats-token")

        snapshot = build_retrieval_stats(
            retrieve_svc=_FailingStats(),
            session_id="test-session",
        )

        assert snapshot.retrieve_available is False
        assert snapshot.last_strategy == "none"
        assert snapshot.last_hit_count == 0
        assert snapshot.total_retrievals_session == 0
        assert snapshot.last_error == "retrieval_stats_query_failed"
        assert "secret" not in snapshot.model_dump_json()


class TestRuntimeIntrospectionDigest:
    def test_format_introspection_digest_with_caps(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            format_introspection_digest,
            MemoryRuntimeSnapshot,
            RetrievalStatsSnapshot,
        )

        memory = MemoryRuntimeSnapshot(
            session_records=100,
            agent_records=50,
            global_records=200,
            total_records=350,
            memory_available=True,
            recent_highlights=["A" * 100, "B" * 100, "C" * 100],
            snapshot_timestamp="2025-01-15T10:30:00Z",
        )

        retrieval = RetrievalStatsSnapshot(
            last_strategy="semantic",
            last_hit_count=10,
            retrieve_available=True,
            snapshot_timestamp="2025-01-15T10:30:00Z",
        )

        digest = format_introspection_digest(
            memory=memory,
            retrieval=retrieval,
            max_tokens=50,
        )

        assert digest.introspection_active is True
        assert digest.capped is True
        assert digest.cap_reason is not None
        assert "Token cap exceeded" in digest.cap_reason


class TestIntrospectionResponseFormatter:
    def test_format_introspection_response_with_full_data(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            MemoryRuntimeSnapshot,
            RetrievalStatsSnapshot,
            RuntimeIntrospectionDigest,
        )

        memory = MemoryRuntimeSnapshot(
            session_records=5,
            agent_records=3,
            global_records=10,
            total_records=18,
            memory_available=True,
            vector_search_available=True,
            recent_highlights=[
                "User likes Python",
                "Project: AI assistant",
                "Session started 2025-03-06",
            ],
            snapshot_timestamp="2025-01-15T10:30:00Z",
        )

        retrieval = RetrievalStatsSnapshot(
            last_strategy="semantic",
            last_hit_count=5,
            retrieve_available=True,
            total_retrievals_session=10,
            snapshot_timestamp="2025-01-15T10:30:00Z",
        )

        digest = RuntimeIntrospectionDigest(
            introspection_active=True,
            memory=memory,
            retrieval=retrieval,
            summary_text="Memory: 18 records, Retrieval: semantic",
            estimated_tokens=100,
        )

        assert digest.memory is not None
        assert digest.memory.total_records == 18
        assert digest.retrieval is not None
        assert digest.retrieval.last_strategy == "semantic"

    def test_format_introspection_response_degraded(self) -> None:
        from openminion.modules.memory.diagnostics.introspection import (
            MemoryRuntimeSnapshot,
            RuntimeIntrospectionDigest,
        )

        memory = MemoryRuntimeSnapshot(
            degraded=True,
            degraded_reason="connection_timeout",
            memory_available=False,
            snapshot_timestamp="2025-01-15T10:30:00Z",
        )

        digest = RuntimeIntrospectionDigest(
            introspection_active=True,
            memory=memory,
            summary_text="Memory degraded: connection_timeout",
            estimated_tokens=50,
        )

        assert digest.memory is not None
        assert digest.memory.degraded is True
        assert digest.memory.degraded_reason == "connection_timeout"
