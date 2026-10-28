"""`storage migrate --backend postgres` entries carry the report error (#446)."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
import uuid

import pytest

from openminion.cli.commands.storage import run_storage_migrate
from tests.storage.postgres_test_utils import schema_url

pytestmark = pytest.mark.postgres


def test_postgres_module_migration_reports_success_and_failure(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    sa = pytest.importorskip("sqlalchemy")
    postgres_url = str(os.getenv("OPENMINION_TEST_POSTGRES_URL", "")).strip()
    if not postgres_url:
        pytest.skip("OPENMINION_TEST_POSTGRES_URL is not set")

    schema_name = f"migrate_report_{uuid.uuid4().hex}"
    admin_engine = sa.create_engine(postgres_url, future=True)
    with admin_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema_name}"'))
    scoped_url = schema_url(postgres_url, schema_name)
    args = SimpleNamespace(
        backend="postgres",
        postgres_url=scoped_url,
        sqlite=str(tmp_path / "openminion.db"),
        module="secret",
        plan=False,
        verify=False,
        json=True,
    )
    try:
        run_storage_migrate(args)
        assert json.loads(capsys.readouterr().out)["modules"] == [
            {"module_id": "secret", "status": "ok", "success": True}
        ]

        engine = sa.create_engine(scoped_url, future=True)
        try:
            with engine.begin() as conn:
                conn.execute(
                    sa.text(
                        "UPDATE alembic_version SET version_num = '9999_not_a_revision'"
                    )
                )
        finally:
            engine.dispose()

        with pytest.raises(SystemExit) as exc:
            run_storage_migrate(args)

        assert exc.value.code == 1
        (entry,) = json.loads(capsys.readouterr().out)["modules"]
        assert entry["status"] == "error"
        assert entry["success"] is False
        assert "9999_not_a_revision" in entry["error"]
        assert "applied" not in entry
    finally:
        with admin_engine.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
        admin_engine.dispose()
