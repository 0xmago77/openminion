"""Readonly exports and exact-identity comparisons of canonical scan evidence."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from openminion.modules.tool import preferred_artifact_ref
from openminion.modules.tool.errors import ToolRuntimeError

from .interfaces import OFFLINE_SECURITY_TOOLS, READONLY_SECURITY_TOOLS
from .review import _read_review_artifact
from .schemas import SecurityAuditReport, SecurityScanResult


class ExportSarifArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_ref: str = Field(pattern=r"^artifact://sha256/[0-9a-f]{64}$")


class CompareScansArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baseline_ref: str = Field(pattern=r"^artifact://sha256/[0-9a-f]{64}$")
    current_ref: str = Field(pattern=r"^artifact://sha256/[0-9a-f]{64}$")


def read_evidence(ctx: Any, ref: str) -> SecurityScanResult | SecurityAuditReport:
    if ctx.permission_mode != "readonly":
        raise ToolRuntimeError(
            "POLICY_DENIED", "Derived security evidence requires readonly mode"
        )
    meta = ctx.artifactctl.get(ref)
    producer = (meta.meta_json or {}).get("tool_name")
    if producer not in {*READONLY_SECURITY_TOOLS, *OFFLINE_SECURITY_TOOLS}:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "Unsupported security evidence producer"
        )
    if meta.session_id != ctx.session_id:
        raise ToolRuntimeError(
            "POLICY_DENIED", "Security evidence belongs to another session"
        )
    content, _ = _read_review_artifact(ctx.artifactctl, ref, producer)
    if producer == "security.publish_report":
        return SecurityAuditReport.model_validate_json(content)
    result = SecurityScanResult.model_validate_json(content)
    if result.capability_id != producer or result.scanner != result.adapter_id:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "Security evidence identity does not match its producer"
        )
    return result


def comparison(
    baseline: SecurityScanResult, current: SecurityScanResult
) -> dict[str, Any]:
    reasons = []
    for scan in (baseline, current):
        if (
            not scan.ok
            or scan.status != "completed"
            or scan.truncated
            or scan.error
            or scan.returned_findings != len(scan.findings)
            or scan.total_findings != scan.returned_findings
        ):
            reasons.append("incomplete_scan")
        config = scan.configuration_identity
        if (
            config is None
            or not config.scanner_version
            or config.scanner_version != scan.scanner_version
        ):
            reasons.append("missing_provenance")
        elif (scan.scanner == "trivy" and not config.database_sha256) or (
            scan.scanner == "semgrep" and not config.config_sha256
        ):
            reasons.append("missing_asset_digest")
        if len({item.finding_id for item in scan.findings}) != len(scan.findings):
            reasons.append("duplicate_finding_identity")
    if (
        baseline.scanner != current.scanner
        or baseline.capability_id != current.capability_id
    ):
        reasons.append("different_scanner_or_check")
    old_worker, new_worker = baseline.provenance, current.provenance
    if (
        old_worker is None
        or new_worker is None
        or not old_worker.cleanup_completed
        or not new_worker.cleanup_completed
    ):
        reasons.append("missing_worker_provenance")
    elif old_worker.worker_image_digest != new_worker.worker_image_digest:
        reasons.append("different_worker_image")
    if baseline.configuration_identity != current.configuration_identity:
        reasons.append("different_configuration")
    old_target, new_target = baseline.target_identity, current.target_identity
    if old_target is None or new_target is None:
        reasons.append("missing_target_lineage")
    elif (old_target.kind, old_target.target_id) != (
        new_target.kind,
        new_target.target_id,
    ):
        reasons.append("different_target_lineage")
    if reasons:
        return {"status": "not_comparable", "reason_codes": sorted(set(reasons))}
    before = {item.finding_id for item in baseline.findings}
    after = {item.finding_id for item in current.findings}
    return {
        "status": "comparable",
        "reason_codes": [],
        "added": sorted(after - before),
        "present": sorted(before & after),
        "not_observed": sorted(before - after),
    }


def sarif_run(scan: SecurityScanResult, ref: str) -> dict[str, Any]:
    results = []
    for finding in scan.findings:
        item: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "message": {"text": finding.message},
            "level": {"critical": "error", "high": "error", "medium": "warning"}.get(
                finding.normalized_severity, "note"
            ),
            "partialFingerprints": {"openminionScannerFinding/v1": finding.finding_id},
            "properties": {
                "review_status": "unreviewed",
                "severity": finding.severity,
                "category": finding.category,
                "source_ref": ref,
            },
        }
        if scan.target_identity and scan.target_identity.kind == "container_archive":
            if finding.component:
                item["locations"] = [
                    {
                        "logicalLocations": [
                            {
                                "name": finding.component,
                                "kind": "module",
                                "properties": {
                                    "installed_version": finding.installed_version
                                },
                            }
                        ]
                    }
                ]
        else:
            path = PurePosixPath(finding.location.path)
            if (
                finding.location.path
                and not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in finding.location.path
            ):
                location: dict[str, Any] = {
                    "artifactLocation": {"uri": quote(path.as_posix(), safe="/")}
                }
                if finding.location.line and finding.location.line > 0:
                    location["region"] = {"startLine": finding.location.line}
                item["locations"] = [{"physicalLocation": location}]
        results.append(item)
    complete = (
        scan.ok
        and scan.status == "completed"
        and not scan.truncated
        and scan.error is None
    )
    return {
        "tool": {"driver": {"name": scan.scanner, "version": scan.scanner_version}},
        "invocations": [{"executionSuccessful": complete}],
        "results": results,
        "properties": {
            "source_ref": ref,
            "review_status": "unreviewed",
            "scan_status": scan.status,
            "truncated": scan.truncated,
            "total_findings": scan.total_findings,
        },
    }


def export_sarif_handler(args: Any, ctx: Any) -> dict[str, Any]:
    parsed = ExportSarifArgs.model_validate(args)
    evidence = read_evidence(ctx, parsed.input_ref)
    if isinstance(evidence, SecurityScanResult):
        runs = [sarif_run(evidence, parsed.input_ref)]
    else:
        runs = []
        for check in evidence.checks:
            scan = read_evidence(ctx, check.evidence_ref)
            if not isinstance(scan, SecurityScanResult):
                raise ToolRuntimeError(
                    "INVALID_ARGUMENT", "Report check does not name scan evidence"
                )
            run = sarif_run(scan, check.evidence_ref)
            for result in run["results"]:
                native_id = result["partialFingerprints"]["openminionScannerFinding/v1"]
                result["properties"]["report_findings"] = [
                    {
                        "finding_id": finding.finding_id,
                        "disposition": finding.disposition,
                        "title": finding.title,
                        "severity": finding.severity,
                    }
                    for finding in evidence.findings
                    if finding.evidence_ref == check.evidence_ref
                    and native_id in finding.scanner_finding_ids
                ]
            runs.append(run)
        manual = [finding for finding in evidence.findings if finding.basis == "manual"]
        if manual:
            runs.append(
                {
                    "tool": {"driver": {"name": "OpenMinion manual assessment"}},
                    "invocations": [
                        {
                            "executionSuccessful": evidence.execution_status
                            == "completed"
                        }
                    ],
                    "results": [
                        {
                            "ruleId": finding.category,
                            "message": {"text": finding.description},
                            "properties": {
                                "review_status": "unreviewed",
                                "disposition": finding.disposition,
                                "finding_id": finding.finding_id,
                                "severity": finding.severity,
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": quote(location.path, safe="/")
                                        },
                                        **(
                                            {"region": {"startLine": location.line}}
                                            if location.line
                                            else {}
                                        ),
                                    }
                                }
                                for location in finding.locations
                            ],
                        }
                        for finding in manual
                    ],
                    "properties": {
                        "source_ref": parsed.input_ref,
                        "review_status": "unreviewed",
                    },
                }
            )
        for run in runs:
            run["properties"]["source_report_ref"] = parsed.input_ref
            run["properties"]["report_execution_status"] = evidence.execution_status
    result = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }
    ref = preferred_artifact_ref(
        ctx.write_artifact(
            "security/export.sarif",
            json.dumps(result, sort_keys=True).encode(),
            "application/sarif+json",
            durable=True,
        )
    )
    return {
        "artifact_ref": ref,
        "artifact_refs": [ref],
        "source_ref": parsed.input_ref,
        "review_status": "unreviewed",
        "compatibility": "schema_only",
    }


def compare_scans_handler(args: Any, ctx: Any) -> dict[str, Any]:
    parsed = CompareScansArgs.model_validate(args)
    baseline = read_evidence(ctx, parsed.baseline_ref)
    current = read_evidence(ctx, parsed.current_ref)
    if not isinstance(baseline, SecurityScanResult) or not isinstance(
        current, SecurityScanResult
    ):
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "Comparison requires two normalized scans"
        )
    result = {
        "schema_version": "security-scan-comparison/v1",
        **parsed.model_dump(),
        **comparison(baseline, current),
        "review_status": "unreviewed",
        "limitations": "Exact scanner IDs only. Not observed does not mean resolved or safe.",
    }
    ref = preferred_artifact_ref(
        ctx.write_artifact(
            "security/comparison.json",
            json.dumps(result, sort_keys=True).encode(),
            "application/json",
            durable=True,
        )
    )
    return {"ok": True, **result, "artifact_ref": ref, "artifact_refs": [ref]}
