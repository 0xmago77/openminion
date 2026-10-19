from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from openminion.modules.artifact import cli as cli_module
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.artifact.errors import ArtifactCtlError
from openminion.modules.artifact.models import PurgeReport

from .utils import run_cli_command, write_config_file


@pytest.fixture
def cli_ctl(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    ctl = MagicMock()
    ctl.__enter__.return_value = ctl
    ctl.purge.return_value = PurgeReport(
        grace_days=0,
        purged_views=0,
        purged_blobs=0,
        missing_files=0,
    )
    monkeypatch.setattr(cli_module, "ArtifactCtl", lambda _config: ctl)
    return ctl


def test_search_limit_reaches_api_and_cli(tmp_path) -> None:
    config_path = write_config_file(
        tmp_path,
        {"artifactctl": {"views": {"auto_generate": []}}},
    )
    with ArtifactCtl(config_path) as ctl:
        for index in range(125):
            ctl.ingest_bytes(
                f"matching-{index}".encode(),
                original_name=f"matching-{index}.txt",
            )

        assert len(ctl.search("matching")) == 100
        assert len(ctl.search("matching", limit=125)) == 125

    result = run_cli_command(config_path, ["search", "matching", "--limit", "125"])
    assert len(result["results"]) == 125


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("0", 0), ("0d", 0), ("7", 7), ("7D", 7), (" 7d ", 7)],
)
def test_purge_grace_accepts_whole_days(
    cli_ctl: MagicMock, raw: str, expected: int
) -> None:
    assert cli_module.main(["purge", "--grace", raw]) == 0
    cli_ctl.purge.assert_called_once_with(grace_days=expected)
    cli_ctl.__exit__.assert_called_once()


def test_purge_omitted_grace_uses_config(cli_ctl: MagicMock) -> None:
    assert cli_module.main(["purge"]) == 0
    cli_ctl.purge.assert_called_once_with(grace_days=None)


@pytest.mark.parametrize(
    "raw",
    ["12h", "30m", "3600s", "2.5d", "-1d", "", "later", "1000000d"],
)
def test_purge_grace_rejects_invalid_values_before_purge(
    cli_ctl: MagicMock,
    raw: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_module.main(["purge", f"--grace={raw}"])

    assert exc_info.value.code == 1
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "INVALID_ARGUMENT"
    cli_ctl.purge.assert_not_called()
    cli_ctl.__exit__.assert_called_once()


def test_separated_negative_grace_stays_an_argparse_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    def _construct(_config):
        nonlocal constructed
        constructed = True

    monkeypatch.setattr(cli_module, "ArtifactCtl", _construct)

    with pytest.raises(SystemExit) as exc_info:
        cli_module.main(["purge", "--grace", "-1d"])

    assert exc_info.value.code == 2
    assert constructed is False


def test_artifactctl_constructor_error_remains_unwrapped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _construct(_config):
        raise ArtifactCtlError("CONSTRUCTION_FAILED", "construction failed")

    monkeypatch.setattr(cli_module, "ArtifactCtl", _construct)

    with pytest.raises(ArtifactCtlError) as exc_info:
        cli_module.main(["purge"])

    assert exc_info.value.code == "CONSTRUCTION_FAILED"
    assert capsys.readouterr().out == ""
