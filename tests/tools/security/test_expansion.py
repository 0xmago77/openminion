from __future__ import annotations

import json
from pathlib import Path
import jsonschema
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from pydantic import ValidationError

from openminion.tools.security.aws_snapshot import AwsSnapshot, evaluate
from openminion.tools.security.derived import comparison, sarif_run
from openminion.tools.security.archive_schemas import ScanTargetIdentity, ScanProvenance
from openminion.tools.security import web_checks
from openminion.tools.security.worker import run_bounded
from tests.tools.security.test_audit_report import _scan, audit_context as audit_context


def snapshot():
    return dict(
        schema_version="aws-security-snapshot/v1",
        source="fixture",
        expected_account_id="123456789012",
        caller_account_id="123456789012",
        region="us-east-1",
        captured_at="2026-10-28T00:00:00Z",
        requested_group_ids=["sg-fixture"],
        requested_volume_ids=["vol-fixture"],
        security_groups=[
            dict(
                GroupId="sg-fixture",
                IpPermissions=[
                    dict(
                        IpProtocol="6",
                        FromPort=22,
                        ToPort=3389,
                        IpRanges=[dict(CidrIp="0.0.0.0/0")],
                        Ipv6Ranges=[],
                    )
                ],
            )
        ],
        volumes=[dict(VolumeId="vol-fixture", Encrypted=False)],
        collection_errors=[],
        pagination_remaining=False,
    )


def parse(data):
    return AwsSnapshot.model_validate_json(json.dumps(data))


def test_aws_complete_corrected_and_partial():
    data = snapshot()
    result = evaluate(parse(data), "artifact://sha256/" + "a" * 64)
    assert result["status"] == "completed"
    assert {item["control_id"] for item in result["candidates"]} == {
        "administrative-ingress",
        "unencrypted-volume",
    }
    data["volumes"][0]["Encrypted"] = True
    data["security_groups"][0]["IpPermissions"][0]["IpRanges"] = [
        dict(CidrIp="10.0.0.0/8")
    ]
    assert evaluate(parse(data), "ref")["candidates"] == []
    data["volumes"] = []
    assert evaluate(parse(data), "ref")["status"] == "partial"


@pytest.mark.parametrize(
    "field,value",
    [
        ("caller_account_id", "000000000000"),
        ("captured_at", "2026-10-28T00:00:00+02:00"),
        ("requested_group_ids", [""]),
        ("pagination_remaining", "false"),
        ("unexpected", "value"),
    ],
)
def test_aws_rejects_invalid_facts(field, value):
    data = snapshot()
    data[field] = value
    with pytest.raises(ValidationError):
        parse(data)


@pytest.mark.parametrize("encrypted", [None, "false", 0])
def test_aws_encrypted_is_required_boolean(encrypted):
    data = snapshot()
    data["volumes"][0]["Encrypted"] = encrypted
    with pytest.raises(ValidationError):
        parse(data)


def test_aws_ipv6_and_combined_cidr_limit():
    data = snapshot()
    rule = data["security_groups"][0]["IpPermissions"][0]
    rule.update(IpProtocol="-1", IpRanges=[], Ipv6Ranges=[dict(CidrIpv6="::/0")])
    assert len(evaluate(parse(data), "ref")["candidates"]) == 2
    rule["IpRanges"] = [dict(CidrIp="0.0.0.0/0")] * 100
    with pytest.raises(ValidationError):
        parse(data)


def comparable_scan():
    scan = _scan(check="code", revision="a" * 40, finding=True)
    scan.target_identity = ScanTargetIdentity(
        kind="source_snapshot", target_id="fixture", content_sha256="a" * 64
    )
    scan.provenance = ScanProvenance(
        worker_id="a" * 64,
        worker_image_digest="sha256:" + "b" * 64,
        cleanup_completed=True,
    )
    return scan


def test_comparison_is_exact_and_never_resolution():
    old = comparable_scan()
    new = old.model_copy(deep=True)
    new.findings[0].finding_id = "moved-native-id"
    new.target_identity.content_sha256 = "b" * 64
    result = comparison(old, new)
    assert result["status"] == "comparable"
    assert result["added"] == ["moved-native-id"]
    assert result["not_observed"] == ["scanner-finding-1"]
    assert "resolved" not in result
    new.truncated = True
    assert comparison(old, new) == {
        "status": "not_comparable",
        "reason_codes": ["incomplete_scan"],
    }
    new = old.model_copy(deep=True)
    new.target_identity = None
    assert "missing_target_lineage" in comparison(old, new)["reason_codes"]


@pytest.mark.parametrize(
    "change,reason",
    [
        ("missing", "missing_worker_provenance"),
        ("cleanup", "missing_worker_provenance"),
        ("image", "different_worker_image"),
    ],
)
def test_comparison_requires_complete_matching_worker(change, reason):
    old = comparable_scan()
    new = old.model_copy(deep=True)
    if change == "missing":
        new.provenance = None
    elif change == "cleanup":
        new.provenance.cleanup_completed = False
    else:
        new.provenance.worker_image_digest = "sha256:" + "c" * 64
    result = comparison(old, new)
    assert result["status"] == "not_comparable"
    assert reason in result["reason_codes"]
    assert "not_observed" not in result


def test_sarif_preserves_incomplete_and_logical_locations():
    scan = comparable_scan()
    scan.truncated = True
    run = sarif_run(scan, "ref")
    assert not run["invocations"][0]["executionSuccessful"]
    assert run["results"][0]["properties"]["review_status"] == "unreviewed"
    assert "baselineState" not in run["results"][0]
    scan.target_identity.kind = "container_archive"
    scan.findings[0].component = "openssl"
    run = sarif_run(scan, "ref")
    assert "logicalLocations" in run["results"][0]["locations"][0]


def test_worker_stops_output_before_child_finishes(tmp_path):
    marker = tmp_path / "continued"
    with pytest.raises(ValueError, match="output"):
        run_bounded(
            [
                sys.executable,
                "-c",
                "import sys,time,pathlib;sys.stdout.write('x'*8192);sys.stdout.flush();time.sleep(1);pathlib.Path(sys.argv[1]).touch()",
                str(marker),
            ],
            tmp_path,
            1024,
        )
    assert not marker.exists()


def test_web_default_invocation_and_identity_prerequisite(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["web_checks"])
    monkeypatch.setattr(
        web_checks,
        "observe",
        lambda check, timeout: dict(
            check_id=check, status="completed", expectation_matched=False, observed={}
        ),
    )
    assert web_checks.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert len(result["checks"]) == 7
    assert {
        row["error_code"] for row in result["checks"] if row["status"] == "incomplete"
    } == {"identity_prerequisite_failed"}
    with pytest.raises(ValueError):
        web_checks.run_checks(["role-denied"], "admin")


def test_web_slow_body_hits_request_deadline(monkeypatch):
    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            try:
                for _ in range(20):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    server = HTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    real_connection = web_checks.http.client.HTTPConnection
    monkeypatch.setattr(
        web_checks.http.client,
        "HTTPConnection",
        lambda host, port, timeout: real_connection(
            host, server.server_port, timeout=timeout
        ),
    )
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            web_checks.observe("user-allowed", timeout=0.15)
        assert time.monotonic() - started < 0.5
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_export_matches_pinned_oasis_schema():
    schema = json.loads(
        (Path(__file__).parent / "fixtures/sarif-schema-2.1.0.json").read_text()
    )
    document = {"version": "2.1.0", "runs": [sarif_run(comparable_scan(), "ref")]}
    jsonschema.Draft7Validator(schema).validate(document)


def test_scan_telemetry_preserves_structural_proof_only():
    from openminion.modules.tool.diagnostics.events import structural_result_fields
    from openminion.modules.telemetry.trace.metadata import structural_tool_payload

    scan = comparable_scan()
    payload = scan.model_dump(mode="json")
    payload.update(
        content="SECRET_CANARY", stdout="SECRET_CANARY", authorization="SECRET_CANARY"
    )
    payload["target_identity"]["target_id"] = "/private/SECRET_CANARY"
    fields = structural_result_fields(payload)
    assert fields["input_sha256"] == "a" * 64
    assert fields["scan_mode"] == "code"
    assert "SECRET_CANARY" not in json.dumps(fields)
    trace = structural_tool_payload(
        {
            "structural_only": True,
            "tool_results": [
                {
                    "tool_name": "security.scan_snapshot",
                    "ok": True,
                    "structural_only": True,
                    "data": fields,
                }
            ],
        }
    )
    assert trace["tool_results"][0]["data"]["input_sha256"] == "a" * 64


def test_structural_security_projection_is_idempotent():
    from openminion.modules.tool.diagnostics.events import structural_tool_results

    item = dict(
        tool_name="security.scan_snapshot",
        ok=True,
        verified=True,
        data=comparable_scan().model_dump(mode="json"),
    )
    once = structural_tool_results([item])
    assert structural_tool_results(once) == once


def test_export_preserves_rejected_interpretation_and_session_access(audit_context):  # noqa: F811
    from openminion.modules.tool import preferred_artifact_ref
    from openminion.modules.tool.errors import ToolRuntimeError
    from openminion.tools.security.derived import export_sarif_handler
    from openminion.tools.security.plugin import _h_publish_report
    from tests.tools.security.test_audit_report import _publish_args

    ctx, revision = audit_context
    ctx.agent_id, ctx.trace_id = "security-fixture", "trace"
    ctx.tool_name = "security.scan_code"
    scan = _scan(check="code", revision=revision, finding=True)
    scan_ref = preferred_artifact_ref(
        ctx.write_artifact(
            "security/scan.json",
            scan.model_dump_json().encode(),
            "application/json",
            durable=True,
        )
    )
    finding = dict(
        finding_id="assessment-1",
        basis="scanner",
        disposition="rejected",
        title="Fixture false positive",
        category="code",
        severity="high",
        confidence="high",
        description="The fixture result was reviewed and rejected.",
        impact="No assessed impact.",
        validation="Synthetic fixture interpretation.",
        recommendation="Retain the evidence.",
        locations=[{"path": "app.py", "line": 1}],
        evidence_ref=scan_ref,
        scanner_finding_ids=["scanner-finding-1"],
    )
    ctx.tool_name = "security.publish_report"
    report = _h_publish_report(
        _publish_args(revision=revision, refs={"code": scan_ref}, findings=[finding]),
        ctx,
    )
    ctx.tool_name = "security.export_sarif"
    exported = export_sarif_handler({"input_ref": report["report_ref"]}, ctx)
    sarif = json.loads(ctx.artifactctl.read_bytes(exported["artifact_ref"]))
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["report_findings"][0]["disposition"] == "rejected"
    assert result["properties"]["review_status"] == "unreviewed"
    assert sarif["runs"][0]["properties"]["source_report_ref"] == report["report_ref"]
    ctx.session_id = "other-session"
    with pytest.raises(ToolRuntimeError, match="another session"):
        export_sarif_handler({"input_ref": report["report_ref"]}, ctx)


def test_aws_snapshot_is_session_bound_and_incomplete_stays_partial(audit_context):  # noqa: F811
    from openminion.modules.tool.errors import ToolRuntimeError
    from openminion.tools.security.aws_snapshot import evaluate_snapshot_handler

    ctx, _ = audit_context
    data = snapshot()
    data["pagination_remaining"] = True
    ref = ctx.artifactctl.ingest_bytes(
        json.dumps(data).encode(), mime="application/json", session_id=ctx.session_id
    ).ref
    ctx.tool_name = "security.evaluate_aws_snapshot"
    result = evaluate_snapshot_handler({"input_ref": ref}, ctx)
    assert result["status"] == "partial" and result["source"] == "fixture"
    assert ctx.artifactctl.read_bytes(result["artifact_ref"])
    ctx.session_id = "other"
    with pytest.raises(ToolRuntimeError, match="access"):
        evaluate_snapshot_handler({"input_ref": ref}, ctx)


def test_web_headers_never_export_secret_values(monkeypatch):
    from types import SimpleNamespace

    response = SimpleNamespace(
        status=200,
        read=lambda _: b"",
        getheaders=lambda: [
            (
                "Set-Cookie",
                "token=HEADER_SECRET_CANARY; Secure; HttpOnly; SameSite=Strict",
            )
        ],
        getheader=lambda key, default="": {
            "Content-Type": "HEADER_SECRET_CANARY",
            "Content-Security-Policy": "HEADER_SECRET_CANARY",
        }.get(key, default),
    )
    connection = SimpleNamespace(
        request=lambda *args, **kwargs: None,
        getresponse=lambda: response,
        close=lambda: None,
    )
    monkeypatch.setattr(
        web_checks.http.client, "HTTPConnection", lambda *args, **kwargs: connection
    )
    result = web_checks.observe("headers", timeout=1)
    assert "HEADER_SECRET_CANARY" not in json.dumps(result)
    assert result["observed"]["content_type"] == "other"
    assert result["observed"]["cookie_attributes"] == [
        {"secure": True, "httponly": True, "samesite": "strict"}
    ]
