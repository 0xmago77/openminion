"""SDK turns apply memory retention once per session with a SQLite store.

This is the control for the PostgreSQL case in
``test_runtime_memory_postgres.py`` (#392).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests._memory_retention_scenarios import check_session_lifecycle_runs_once


def test_sdk_session_lifecycle_applies_retention_once_per_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    check_session_lifecycle_runs_once(tmp_path / "root", monkeypatch, caplog, None)
