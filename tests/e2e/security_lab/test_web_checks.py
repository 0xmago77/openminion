from pathlib import Path

import json
import pytest

from tests.e2e.security_lab.fixture import local_lab
from tests.e2e.security_lab.test_local_lab import (
    lab_context as lab_context,
    _execute,
    _stdout,
)

pytestmark = pytest.mark.e2e


@pytest.fixture(params=[False, True], ids=["vulnerable", "corrected"])
def real_lab(tmp_path, monkeypatch, request):
    for key, name in (
        ("OPENMINION_HOME", "home"),
        ("OPENMINION_DATA_ROOT", "data"),
        ("OPENMINION_GENERATED_ROOT", "generated"),
    ):
        monkeypatch.setenv(key, str(tmp_path / name))
    script = (
        Path(__file__).resolve().parents[3] / "examples/security/offline/web_fixture.py"
    ).read_text()
    script = (
        "import sys\nsys.argv = ['fixture'"
        + (", '--corrected'" if request.param else "")
        + "]\n"
        + script
    )
    with local_lab(tmp_path, target_script=script) as lab:
        lab.corrected = request.param
        yield lab


def test_fixed_web_matrix(real_lab, lab_context):  # noqa: F811
    result = _execute(lab_context, "python3 -B /opt/security/web_checks.py")
    assert result["exit_code"] == 0, result
    observations = json.loads(_stdout(lab_context, result))
    assert observations["status"] == "completed"
    checks = {item["check_id"]: item for item in observations["checks"]}
    assert len(checks) == 7
    assert checks["user-allowed"]["observed"]["marker_matched"]
    for check in ("role-denied", "object-denied"):
        assert checks[check]["expectation_matched"] is real_lab.corrected
    assert checks["headers"]["observed"]["nosniff"] is real_lab.corrected
    assert checks["redirect-contained"]["observed"]["http_status"] == 302
    assert "synthetic" not in json.dumps(observations)
