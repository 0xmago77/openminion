"""Explicit installed-Semgrep proof; excluded from ordinary hosted E2E selection."""

import json
import os

import pytest

from tests.e2e.project_worker.test_security_remediation import run_security_lifecycle
from tests.tools.security.test_audit_report import audit_context as audit_context

pytestmark = pytest.mark.e2e


def test_installed_semgrep_remediation_lifecycle(audit_context, tmp_path):
    if os.environ.get("OPENMINION_TEST_INSTALLED_SECURITY") != "1":
        pytest.skip(
            "set OPENMINION_TEST_INSTALLED_SECURITY=1 for installed scanner proof"
        )
    ctx, _ = audit_context
    evidence = run_security_lifecycle(ctx, tmp_path, installed=True)
    (tmp_path / "lifecycle-evidence.json").write_text(json.dumps(evidence, indent=2))
