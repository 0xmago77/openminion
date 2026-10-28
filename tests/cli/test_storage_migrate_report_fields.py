"""`storage migrate` entries report what the `MigrationReport` holds (#446)."""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from openminion.cli.commands.storage import run_storage_migrate
from openminion.modules.storage.migrations.models import (
    BackupArtifact,
    DbState,
    MigrationReport,
    VerificationReport,
)

_LOCATE_ERROR = (
    "Alembic upgrade failed for module 'secret': "
    "Can't locate revision identified by '9999_not_a_revision'"
)


def _args(**overrides) -> SimpleNamespace:
    values = {
        "sqlite": "",
        "backend": "sqlite",
        "postgres_url": "",
        "module": "secret",
        "plan": False,
        "verify": False,
        "json": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _state(revision: str | None) -> DbState:
    return DbState(
        module_id="secret",
        db_path="secret.db",
        exists=True,
        application_id=None,
        expected_application_id=None,
        application_id_matches=True,
        user_version=0,
        alembic_revision=revision,
    )


def _report(
    *, success: bool, error: str | None = None, rolled_back: bool = False
) -> MigrationReport:
    return MigrationReport(
        module_id="secret",
        db_path="secret.db",
        target="head",
        before=_state(None),
        after=_state("0001_baseline" if success else None),
        backup=BackupArtifact(
            module_id="secret",
            source_db_path="secret.db",
            snapshot_path="secret.db.bak",
            mode="file_copy",
            created_at="2026-10-28T00:00:00+00:00",
            user_version=0,
            schema_head=None,
        ),
        verification=VerificationReport(
            module_id="secret",
            db_path="secret.db",
            level="quick",
            quick_check="ok",
            integrity_check=None,
        ),
        success=success,
        duration_ms=1,
        rolled_back=rolled_back,
        error=error,
    )


def _run(args, runner) -> int:
    with patch("openminion.cli.commands.storage._make_runner", return_value=runner):
        try:
            run_storage_migrate(args)
        except SystemExit as exc:
            return int(exc.code)
    return 0


def _entries(capsys: pytest.CaptureFixture[str]) -> list[dict]:
    return json.loads(capsys.readouterr().out)["modules"]


def test_failed_report_json_entry_carries_the_report_error(capsys) -> None:
    runner = MagicMock()
    runner.migrate.return_value = _report(success=False, error=_LOCATE_ERROR)

    code = _run(_args(json=True), runner)

    assert code == 1
    assert _entries(capsys) == [
        {
            "module_id": "secret",
            "status": "error",
            "success": False,
            "error": _LOCATE_ERROR,
        }
    ]


def test_successful_report_json_entry_has_no_error_and_no_empty_applied_list(
    capsys,
) -> None:
    runner = MagicMock()
    runner.migrate.return_value = _report(success=True)

    code = _run(_args(json=True), runner)

    assert code == 0
    assert _entries(capsys) == [
        {"module_id": "secret", "status": "ok", "success": True}
    ]


def test_failed_verified_report_json_entry_carries_the_report_error(capsys) -> None:
    message = "Post-migration verification failed with fatal findings."
    runner = MagicMock()
    runner.migrate_with_verify.return_value = _report(
        success=False, error=message, rolled_back=True
    )

    code = _run(_args(json=True, verify=True), runner)

    assert code == 1
    runner.migrate_with_verify.assert_called_once_with(target="head")
    assert _entries(capsys)[0]["error"] == message


def test_failed_report_text_output_prints_the_report_error(capsys) -> None:
    runner = MagicMock()
    runner.migrate.return_value = _report(success=False, error=_LOCATE_ERROR)

    code = _run(_args(), runner)

    assert code == 1
    assert capsys.readouterr().out == f"  FAIL  secret: {_LOCATE_ERROR}\n"


def test_successful_report_text_output_is_unchanged(capsys) -> None:
    runner = MagicMock()
    runner.migrate.return_value = _report(success=True)

    code = _run(_args(), runner)

    assert code == 0
    assert capsys.readouterr().out == "  ok  secret\n"


def test_raised_error_entry_is_unchanged(capsys) -> None:
    runner = MagicMock()
    runner.migrate.side_effect = RuntimeError("boom")

    code = _run(_args(json=True), runner)

    assert code == 1
    assert _entries(capsys) == [
        {"module_id": "secret", "status": "error", "error": "boom"}
    ]


def test_sqlite_module_migration_reports_success_and_failure(tmp_path, capsys) -> None:
    db_path = tmp_path / "secret.db"
    sqlite3.connect(db_path).close()
    args = _args(sqlite=str(db_path), json=True)

    run_storage_migrate(args)
    assert _entries(capsys) == [
        {"module_id": "secret", "status": "ok", "success": True}
    ]

    connection = sqlite3.connect(db_path)
    try:
        with connection:
            connection.execute(
                "UPDATE alembic_version SET version_num = '9999_not_a_revision'"
            )
    finally:
        connection.close()

    with pytest.raises(SystemExit) as exc:
        run_storage_migrate(args)

    assert exc.value.code == 1
    (entry,) = _entries(capsys)
    assert entry["status"] == "error"
    assert entry["success"] is False
    assert "9999_not_a_revision" in entry["error"]
    assert "applied" not in entry
