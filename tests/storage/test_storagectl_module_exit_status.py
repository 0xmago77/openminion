"""`python -m openminion.modules.storage` exits with storagectl's status.

Each test calls `cli.main` in-process and runs the package entry point in a
subprocess on the same source tree with the same arguments. The process must
exit with the value `main()` returns and print what `main()` prints. A command
that raises keeps exiting 1 with the exception's traceback.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from openminion.modules.storage import cli as storage_cli

# The source root this test imported openminion from (`src`), so the
# subprocess runs the same code as the in-process `main()` call.
_SOURCE_ROOT = Path(storage_cli.__file__).resolve().parents[3]


def _run_module(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(_SOURCE_ROOT), env.get("PYTHONPATH", "")) if part
    )
    return subprocess.run(
        [sys.executable, "-m", "openminion.modules.storage", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_module_exits_zero_with_main_output_on_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ("plan", "--namespace", "session", "--sqlite", str(tmp_path / "session.db"))
    assert storage_cli.main(list(args)) == 0
    expected = capsys.readouterr()
    assert json.loads(expected.out)["ok"] is True

    result = _run_module(tmp_path, *args)

    assert result.returncode == 0, result.stderr
    assert result.stdout == expected.out
    assert result.stderr == expected.err


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(("pool-stats",), id="pool-stats-without-postgres-url"),
        pytest.param(
            ("a2a-archive-old", "--older-than-days", "0"),
            id="a2a-archive-old-zero-days",
        ),
    ],
)
def test_module_exits_with_main_nonzero_status_and_same_output(
    args: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("OPENMINION_STORAGE_POSTGRES_URL", raising=False)
    status = storage_cli.main(list(args))
    expected = capsys.readouterr()
    assert status == 2
    assert json.loads(expected.out)["ok"] is False

    result = _run_module(tmp_path, *args)

    assert result.returncode == status
    assert result.stdout == expected.out
    assert result.stderr == expected.err


def test_module_still_exits_one_when_main_raises(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = (
        "plan",
        "--namespace",
        "unknown-module",
        "--sqlite",
        str(tmp_path / "unknown.db"),
    )
    with pytest.raises(ValueError, match="unknown-module") as raised:
        storage_cli.main(list(args))
    assert capsys.readouterr().out == ""

    result = _run_module(tmp_path, *args)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.rstrip().splitlines()[-1] == f"ValueError: {raised.value}"
