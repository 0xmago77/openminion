"""Opt-in MiniMax proof for the new offline security tools."""

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from collections import Counter

import pytest

from openminion.cli.commands.daemon import daemon_stop
from openminion.base.types import Message
from openminion.services.brain.post_execution.context import _resolve_turn_session_ids
from openminion.modules.tool.diagnostics.events import structural_tool_results
from openminion.modules.artifact.config import (
    ArtifactCtlConfig,
    BlobStoreConfig,
    IndexConfig,
)
from openminion.modules.artifact.control import ArtifactCtl
from tests.e2e.cli.focus.harness import FocusProbe, FocusScenario
from tests.e2e.cli.focus.harness.artifacts import artifact_root, write_transcript
from tests.e2e.cli.focus.harness.probe import focus_session_id
from tests.e2e.cli.focus.harness.assertions import read_focus_evidence
from tests.e2e.cli.focus.test_live_goal_only import _events, _usage
from tests.e2e.cli.focus.test_live_security_local_lab import _configuration
from tests.e2e.cli.focus.test_live_security_researcher import (
    _install_profile,
)
from tests.e2e.security_lab.test_offline_scan import snapshot
from tests.tools.security.test_expansion import snapshot as aws_snapshot

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(900)]
_AGENT = "security-researcher-offline"


def test_live_offline_security_tools(
    tmp_path, python_bin, openminion_root, framework_root, monkeypatch
):
    if os.environ.get("OPENMINION_LIVE_SECURITY_EXPANSION") != "1":
        pytest.skip(
            "Set OPENMINION_LIVE_SECURITY_EXPANSION=1 for the explicit MiniMax run"
        )
    assert os.getenv("OPENMINION_LIVE_CLI_FOCUS_E2E") == "1"
    assert os.getenv("OPENMINION_TEST_OFFLINE_SECURITY_SCAN") == "1"
    root = artifact_root(tmp_path) / "security-expansion"
    root.mkdir(parents=True, exist_ok=True)
    path, settings = _configuration(root, monkeypatch)
    evidence = {"status": "failed", **settings}
    started = time.monotonic()
    payload = json.loads(path.read_text())
    profile = next(iter(payload["agents"].values()))
    profile.update(name=_AGENT, skill=_AGENT)
    payload.update(default_agent=_AGENT, agents={_AGENT: profile})
    target = root / "archives"
    target.mkdir()
    before = snapshot(target / "before.tar", {"app.py": b"eval(input())\n"})
    after = snapshot(target / "after.tar", {"app.py": b"print(input())\n"})
    image_archive = Path(os.environ["OPENMINION_TEST_SECURITY_IMAGE_ARCHIVE"])
    image = target / "image.tar"
    shutil.copyfile(image_archive, image)
    scan_config = root / "scan-config.json"
    scan_config.write_text(
        json.dumps(
            {
                "docker": {
                    "daemon_socket": os.environ[
                        "OPENMINION_TEST_SECURITY_LAB_DOCKER_SOCKET"
                    ],
                    "worker_image": os.environ["OPENMINION_TEST_SECURITY_SCAN_IMAGE"],
                },
                "targets": {
                    "source": {"root": str(target), "kind": "source_snapshot"},
                    "image": {"root": str(target), "kind": "container_archive"},
                },
            }
        )
    )
    payload["runtime"]["env"] = {"OPENMINION_SECURITY_SCAN_CONFIG": str(scan_config)}
    path.write_text(json.dumps(payload))
    data_root = root / "data"
    session_id = focus_session_id(data_root=data_root, node_name="security-expansion")
    probe = FocusProbe(
        python_bin=python_bin,
        openminion_root=openminion_root,
        framework_root=framework_root,
        data_root=data_root,
        config_path=path,
        agent_id=_AGENT,
        workdir=target,
        session_id=session_id,
        include_project_context=False,
        allow_unsandboxed_exec=False,
    )
    env = {**os.environ, **probe.environment()}
    _install_profile(
        python_bin=python_bin,
        openminion_root=openminion_root,
        env=env,
        profile_name=_AGENT,
        config_path=path,
    )
    artifact_config = ArtifactCtlConfig(
        blob_store=BlobStoreConfig(root_dir=str(data_root / "artifact")),
        index=IndexConfig(sqlite_path=str(data_root / "artifact/index.db")),
    )
    evidence.update(
        candidate_sha=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=openminion_root, text=True
        ).strip(),
        session_id=session_id,
        worker_image=os.environ["OPENMINION_TEST_SECURITY_SCAN_IMAGE"],
        inputs={
            file.name: sha256(file.read_bytes()).hexdigest()
            for file in (before, after, image)
        },
    )
    try:
        with probe.session(
            rows=52,
            cols=160,
            on_transcript_update=lambda text: write_transcript(
                root, "security-expansion", text
            ),
        ) as session:
            try:
                probe.wait_ready(session)
                probe.run_slash(session, "/readonly on", marker="read-only mode: ON")
                for exposure in ("security_offline", "security_reporting"):
                    probe.run_slash(
                        session,
                        f"/tools activate {exposure} approved=yes",
                        marker=f"Activated: {exposure}",
                    )
                _, canonical_session_id = _resolve_turn_session_ids(
                    message=Message(
                        channel="console",
                        target="focus",
                        body="",
                        metadata={
                            "session_id": session_id,
                            "conversation_id": "focus-" + session_id,
                        },
                    )
                )
                with ArtifactCtl(artifact_config) as ctl:
                    input_ref = ctl.ingest_bytes(
                        json.dumps(aws_snapshot()).encode(),
                        mime="application/json",
                        session_id=canonical_session_id,
                    ).ref
                evidence.update(
                    canonical_session_id=canonical_session_id, aws_input_ref=input_ref
                )
                scenario = FocusScenario(
                    scenario_id="security-expansion",
                    timeout=900,
                    expected_markers=("artifact://sha256/",),
                    prompt=(
                        "Execute this security audit task using the activated tools in readonly mode. Run each requested operation once; use adaptive tool execution. "
                        f"Use security.scan_snapshot check=code target_id=source on {before} expected_sha256={sha256(before.read_bytes()).hexdigest()}, "
                        f"then on {after} expected_sha256={sha256(after.read_bytes()).hexdigest()}. "
                        "Compare their returned canonical scan evidence_refs using security.compare_scans, before as baseline and after as current. "
                        "Export the first scan evidence to SARIF using security.export_sarif. "
                        f"Use security.scan_image target_id=image archive={image} expected_sha256={sha256(image.read_bytes()).hexdigest()}. "
                        f"Use security.evaluate_aws_snapshot input_ref={input_ref}. "
                        "End with all canonical output references and statuses. Preserve unreviewed candidate semantics; do not claim resolution or a live cloud scan."
                    ),
                )
                probe.run_turn(session, scenario)
            finally:
                write_transcript(root, "security-expansion", session.visible_transcript)
        _assert_outputs(artifact_config, evidence)
        _assert_terminal(probe, evidence)
        evidence["status"] = "passed"
    finally:
        status = evidence["status"]
        evidence["status"] = "failed"
        evidence["duration_seconds"] = time.monotonic() - started
        events = _events(data_root / "telemetry/telemetry.db", 0)
        evidence["observed_usage"] = _usage(events, session_id, _AGENT)
        try:
            stopped = daemon_stop(
                str(path),
                home_root=probe.environment()["OPENMINION_HOME"],
                data_root=data_root,
            )
            evidence["daemon_stop_exit_code"] = stopped
            assert stopped == 0
            evidence["status"] = status
        finally:
            (root / "evidence.json").write_text(json.dumps(evidence, indent=2))


def _assert_outputs(artifact_config, evidence):
    with ArtifactCtl(artifact_config) as ctl:
        outputs = [
            json.loads(ctl.read_bytes(item.sha256))
            for item in ctl.list_recent(limit=50)
            if (item.meta_json or {}).get("runtime_bridge")
            == "RuntimeContext.write_artifact"
        ]
    scans = [item for item in outputs if "capability_id" in item]
    assert len(scans) == 3
    assert all(item["status"] == "completed" for item in scans)
    comparisons = [
        item
        for item in outputs
        if item.get("schema_version") == "security-scan-comparison/v1"
    ]
    assert len(comparisons) == 1 and comparisons[0]["status"] == "comparable"
    assert comparisons[0]["not_observed"] and not comparisons[0]["added"]
    sarif = [item for item in outputs if item.get("version") == "2.1.0"]
    assert len(sarif) == 1
    assert (
        sarif[0]["runs"][0]["properties"]["source_ref"]
        == comparisons[0]["baseline_ref"]
    )
    assessments = [
        item
        for item in outputs
        if item.get("schema_version") == "aws-security-assessment/v1"
    ]
    assert len(assessments) == 1 and assessments[0]["status"] == "completed"
    assert len(assessments[0]["candidates"]) == 2
    evidence["output_counts"] = {
        "scans": len(scans),
        "comparisons": len(comparisons),
        "aws_candidates": len(assessments[0]["candidates"]),
    }
    evidence["cleanup_completed"] = all(
        scan["provenance"]["cleanup_completed"] for scan in scans
    )
    assert evidence["cleanup_completed"]
    with ArtifactCtl(artifact_config) as ctl:
        evidence["output_refs"] = [
            item.to_ref().ref
            for item in ctl.list_recent(limit=50)
            if (item.meta_json or {}).get("runtime_bridge")
            == "RuntimeContext.write_artifact"
        ]


def _assert_terminal(probe, evidence):
    _, messages, canonical_session_id = read_focus_evidence(
        probe.environment(), probe.session_id
    )
    assert canonical_session_id == evidence["canonical_session_id"]
    outbound = [message for message in messages if message.role == "outbound"]
    assert [message.metadata.get("brain_status") for message in outbound] == ["done"]
    for key in ("tool_results", "tool_calls_cumulative"):
        results = json.loads(outbound[0].metadata[key])
        assert results and results == structural_tool_results(results)
        assert all(not ({"args", "content", "error"} & item.keys()) for item in results)
    events = _events(probe.data_root / "telemetry/telemetry.db", 0)
    requested = {
        (event["execution_id"], event["data"]["call_id"]): event["data"][
            "canonical_name"
        ]
        for event in events
        if event["event_type"] == "tool.call.requested"
    }
    completed = [
        requested[(event["execution_id"], event["data"]["call_id"])]
        for event in events
        if event["event_type"] == "tool.call.completed"
    ]
    expected = Counter(
        {
            "security.scan_snapshot": 2,
            "security.scan_image": 1,
            "security.evaluate_aws_snapshot": 1,
            "security.compare_scans": 1,
            "security.export_sarif": 1,
        }
    )
    assert (
        Counter(tool for tool in completed if tool.startswith("security.")) == expected
    )
    assert (
        Counter(tool for tool in requested.values() if tool.startswith("security."))
        == expected
    )
    assert set(requested.values()) <= set(expected) | {"respond", "clarify"}
    assert not any(event["event_type"] == "tool.call.blocked" for event in events)
    evidence["usage"] = _usage(events, probe.session_id, _AGENT)
    assert evidence["usage"]["campaign_totals_complete"]
    assert (
        evidence["usage"]["input_tokens"] > 0 and evidence["usage"]["output_tokens"] > 0
    )
    evidence["persisted_terminal_status"] = "done"
