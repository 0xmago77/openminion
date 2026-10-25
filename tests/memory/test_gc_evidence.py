"""Memory retention and purge of SQLite items that carry evidence (#400).

The SQLite controls for ``test_gc_evidence_postgres.py``, and the shared
evidence decoder that both backends use.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from openminion.modules.memory.runtime.purge import decode_evidence_ref_values
from openminion.modules.memory.storage.sqlite.store import SQLiteMemoryStore
from tests._memory_evidence_scenarios import (
    ARTIFACT_SHA256,
    CASES,
    RecordingArtifactCtl,
    expected_outcome,
    run_case,
)

ARTIFACT_EVIDENCE = {
    "label": None,
    "mime": "text/plain",
    "ref": ARTIFACT_SHA256,
    "sha256": ARTIFACT_SHA256,
    "size_bytes": 1,
}
CAPTURE_EVIDENCE = {
    "label": "assured-capture",
    "mime": "application/x-openminion-capture",
    "ref": "capture-1",
    "sha256": "b" * 64,
    "size_bytes": 0,
}


@pytest.mark.parametrize(
    "decoded",
    [
        [ARTIFACT_EVIDENCE, CAPTURE_EVIDENCE],
        [ARTIFACT_SHA256],
        [],
    ],
)
def test_decode_evidence_ref_values_keeps_an_already_decoded_list(
    decoded: list[Any],
) -> None:
    # PostgreSQL returns the JSONB evidence_json column as a list.
    assert decode_evidence_ref_values(decoded) == decoded


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        (
            json.dumps([ARTIFACT_EVIDENCE, CAPTURE_EVIDENCE]),
            [ARTIFACT_EVIDENCE, CAPTURE_EVIDENCE],
        ),
        ("[]", []),
        (json.dumps(ARTIFACT_EVIDENCE), []),
        ("", []),
        (None, []),
    ],
)
def test_decode_evidence_ref_values_parses_stored_text_and_empty_values(
    stored: str | None, expected: list[Any]
) -> None:
    assert decode_evidence_ref_values(stored) == expected


def test_decode_evidence_ref_values_still_rejects_text_that_is_not_json() -> None:
    with pytest.raises(json.JSONDecodeError):
        decode_evidence_ref_values("not json")


@pytest.mark.parametrize("case", CASES)
def test_retention_step_removes_sqlite_items_with_evidence(
    case: str, tmp_path: Path
) -> None:
    artifactctl = RecordingArtifactCtl()
    store = SQLiteMemoryStore(tmp_path / "memory.db", artifactctl=artifactctl)
    try:
        assert run_case(case, store, artifactctl) == expected_outcome(case)
    finally:
        store.close()
