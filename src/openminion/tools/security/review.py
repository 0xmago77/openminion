"""Publish independent decisions over immutable source-security reports."""

import uuid
from typing import Any, cast

from pydantic import ValidationError

from openminion.base.redaction import redact_mapping
from openminion.base.time import utc_now_iso
from openminion.modules.artifact.control import ArtifactCtl
from openminion.modules.artifact.errors import ArtifactCtlError
from openminion.modules.artifact.models import ArtifactMeta
from openminion.modules.tool.errors import ToolRuntimeError
from openminion.modules.tool import RuntimeContext

from .interfaces import TOOL_SECURITY_PUBLISH_REPORT, TOOL_SECURITY_REVIEW_REPORT
from .schemas import (
    SecurityAuditFinding,
    SecurityAuditReport,
)
from .review_schemas import (
    SecurityFindingDecision,
    SecurityFindingReview,
    SecurityFollowUpReviewArgs,
    SecurityInitialReviewArgs,
    SecurityRemediationFinding,
)


def _read_review_artifact(
    ctl: ArtifactCtl, ref: str, producer: str
) -> tuple[bytes, ArtifactMeta]:
    try:
        meta = ctl.get(ref)
        provenance = meta.meta_json or {}
        if (
            meta.deleted_at
            or not meta.agent_id
            or not meta.session_id
            or not meta.trace_id
            or provenance.get("runtime_bridge") != "RuntimeContext.write_artifact"
            or provenance.get("tool_name") != producer
        ):
            raise ToolRuntimeError(
                "INVALID_ARGUMENT", "review evidence has invalid provenance"
            )
        return ctl.read_bytes(ref), meta
    except (ArtifactCtlError, OSError) as exc:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "review evidence is unavailable"
        ) from exc


def _read_source_report(
    ctl: ArtifactCtl, ref: str, reviewer: str
) -> tuple[SecurityAuditReport, ArtifactMeta]:
    content, meta = _read_review_artifact(ctl, ref, TOOL_SECURITY_PUBLISH_REPORT)
    report = SecurityAuditReport.model_validate_json(content)
    if meta.agent_id == reviewer:
        raise ToolRuntimeError(
            "POLICY_DENIED", "a report author cannot review their report"
        )
    checks = report.checks
    if (
        report.execution_status != "completed"
        or len(checks) != len(report.scope.requested_checks)
        or {check.check for check in checks} != set(report.scope.requested_checks)
        or any(
            check.status != "completed" or check.truncated or check.error is not None
            for check in checks
        )
    ):
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "review requires complete untruncated checks"
        )
    for evidence_ref in report.evidence_refs:
        try:
            if ctl.get(evidence_ref).deleted_at:
                raise ToolRuntimeError("INVALID_ARGUMENT", "source evidence is deleted")
            ctl.read_bytes(evidence_ref)
        except (ArtifactCtlError, OSError) as exc:
            raise ToolRuntimeError(
                "INVALID_ARGUMENT", "source evidence is unavailable"
            ) from exc
    return report, meta


def _exact_review_ids(actual: list[str], expected: set[str]) -> None:
    if len(actual) != len(expected) or set(actual) != expected:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT",
            "review decisions must cover each required finding exactly once",
            details={
                "expected_finding_ids": sorted(expected),
                "received_finding_ids": actual,
            },
        )


def _candidate_findings(report: SecurityAuditReport) -> dict[str, SecurityAuditFinding]:
    return {
        finding.finding_id: finding
        for finding in report.findings
        if finding.disposition == "candidate"
    }


def _accepted_brief(
    findings: dict[str, SecurityAuditFinding], decisions: list[SecurityFindingDecision]
) -> list[SecurityRemediationFinding]:
    return [
        SecurityRemediationFinding(
            **findings[item.finding_id].model_dump(
                include={
                    "finding_id",
                    "title",
                    "category",
                    "severity",
                    "confidence",
                    "locations",
                    "evidence_ref",
                    "scanner_finding_ids",
                    "evidence_summary",
                }
            ),
            remediation_objective=cast(str, item.remediation_objective),
            verification_criteria=cast(list[str], item.verification_criteria),
        )
        for item in decisions
        if item.decision == "accepted"
    ]


def _initial_review(
    args: SecurityInitialReviewArgs, ctl: ArtifactCtl, reviewer: str
) -> dict[str, Any]:
    report, meta = _read_source_report(ctl, args.report_ref, reviewer)
    candidates = _candidate_findings(report)
    if not candidates:
        raise ToolRuntimeError("INVALID_ARGUMENT", "report has no candidates to review")
    _exact_review_ids(
        [item.finding_id for item in args.finding_reviews], set(candidates)
    )
    statuses = {item.decision for item in args.finding_reviews}
    return {
        "source_report_ref": args.report_ref,
        "assessment_id": report.assessment_id,
        "scope": report.scope,
        "report_author_agent_id": meta.agent_id,
        "review_status": next(iter(statuses)) if len(statuses) == 1 else "mixed",
        "finding_reviews": args.finding_reviews,
        "evidence_refs": [args.report_ref, *report.evidence_refs],
        "remediation_brief": _accepted_brief(candidates, args.finding_reviews),
    }


def _matching_rescan(
    original: SecurityAuditReport, current: SecurityAuditReport
) -> None:
    if (
        original.scope.target != current.scope.target
        or original.scope.target_revision.lower()
        == current.scope.target_revision.lower()
        or set(original.scope.requested_checks) != set(current.scope.requested_checks)
    ):
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "rescan target, revision, or check set is incompatible"
        )
    previous = {check.check: check for check in original.checks}
    for check in current.checks:
        old = previous[check.check]
        if (
            check.tool_id != old.tool_id
            or check.scanner != old.scanner
            or check.scanner_version != old.scanner_version
            or check.configuration_identity != old.configuration_identity
        ):
            raise ToolRuntimeError(
                "INVALID_ARGUMENT", "rescan scanner configuration is incompatible"
            )


def _follow_up_review(
    args: SecurityFollowUpReviewArgs, ctl: ArtifactCtl, reviewer: str
) -> dict[str, Any]:
    content, _ = _read_review_artifact(
        ctl, args.prior_review_ref, TOOL_SECURITY_REVIEW_REPORT
    )
    prior = SecurityFindingReview.model_validate_json(content)
    if prior.review_kind != "initial":
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "follow-up requires an initial review"
        )
    original, author = _read_source_report(ctl, prior.source_report_ref, reviewer)
    current, _ = _read_source_report(ctl, args.rescan_report_ref, reviewer)
    _matching_rescan(original, current)
    accepted = {
        item.finding_id for item in prior.finding_reviews if item.decision == "accepted"
    }
    if not accepted:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "prior review has no accepted findings"
        )
    _exact_review_ids([item.finding_id for item in args.closure_reviews], accepted)
    current_candidates = set(_candidate_findings(current))
    matched = {
        finding_id
        for item in args.closure_reviews
        for finding_id in item.current_finding_ids
    }
    if not matched <= current_candidates:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "closure cites an unknown current candidate"
        )
    _exact_review_ids(
        [item.finding_id for item in args.new_finding_reviews],
        current_candidates - matched,
    )
    statuses = {item.outcome for item in args.closure_reviews}
    actionable = any(item.decision != "rejected" for item in args.new_finding_reviews)
    return {
        "source_report_ref": prior.source_report_ref,
        "assessment_id": original.assessment_id,
        "scope": original.scope,
        "report_author_agent_id": author.agent_id,
        "review_status": next(iter(statuses))
        if len(statuses) == 1 and not actionable
        else "mixed",
        "closure_reviews": args.closure_reviews,
        "new_finding_reviews": args.new_finding_reviews,
        "prior_review_ref": args.prior_review_ref,
        "rescan_report_ref": args.rescan_report_ref,
        "rescan_revision": current.scope.target_revision,
        "evidence_refs": list(
            dict.fromkeys(
                [
                    args.prior_review_ref,
                    prior.source_report_ref,
                    args.rescan_report_ref,
                    *original.evidence_refs,
                    *current.evidence_refs,
                ]
            )
        ),
    }


def _redact_review_prose(report: SecurityFindingReview) -> SecurityFindingReview:
    payload = report.model_dump(mode="json", exclude_none=True)
    prose, count = redact_mapping(
        {"summary": payload["summary"], "limitations": payload["limitations"]}
    )
    payload.update(prose)
    for section in (
        "finding_reviews",
        "closure_reviews",
        "new_finding_reviews",
        "remediation_brief",
    ):
        for item in payload[section]:
            prose, redacted = redact_mapping(
                {
                    key: item[key]
                    for key in (
                        "rationale",
                        "remediation_objective",
                        "verification_criteria",
                        "evidence_requests",
                        "next_step_guidance",
                    )
                    if key in item
                }
            )
            item.update(prose)
            count += redacted
    try:
        report = SecurityFindingReview.model_validate(
            {**payload, "redaction_count": count}
        )
    except ValidationError as exc:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT",
            "redacted review exceeds field limits; shorten the prose",
        ) from exc
    return report


def publish_security_review(
    args: SecurityInitialReviewArgs | SecurityFollowUpReviewArgs, *, ctx: RuntimeContext
) -> dict[str, Any]:
    if ctx.permission_mode != "readonly":
        raise ToolRuntimeError(
            "POLICY_DENIED", "security review requires readonly permission"
        )
    if not ctx.agent_id or not ctx.session_id or not ctx.trace_id:
        raise ToolRuntimeError(
            "POLICY_DENIED",
            "security review requires runtime agent, session and trace identity",
        )
    if ctx.artifactctl is None:
        raise ToolRuntimeError(
            "INTERNAL_ERROR", "security review requires canonical artifact storage"
        )
    try:
        values = (
            _initial_review(args, ctx.artifactctl, ctx.agent_id)
            if isinstance(args, SecurityInitialReviewArgs)
            else _follow_up_review(args, ctx.artifactctl, ctx.agent_id)
        )
    except ValidationError as exc:
        raise ToolRuntimeError(
            "INVALID_ARGUMENT", "review evidence has an invalid schema"
        ) from exc
    report = SecurityFindingReview(
        review_id=uuid.uuid4().hex,
        review_kind=args.review_kind,
        created_at=utc_now_iso(),
        reviewer_agent_id=ctx.agent_id,
        reviewer_session_id=ctx.session_id,
        reviewer_trace_id=ctx.trace_id,
        summary=args.summary,
        limitations=args.limitations,
        redaction_count=0,
        **values,
    )
    report = _redact_review_prose(report)
    artifact = ctx.write_artifact(
        f"security/review-{report.review_id}.json",
        report.model_dump_json(exclude_none=True, indent=2).encode(),
        "application/json",
        durable=True,
    )
    if artifact.canonical_ref is None:
        raise ToolRuntimeError(
            "INTERNAL_ERROR",
            "security review publication requires a canonical artifact",
        )
    return {
        "ok": True,
        "review_id": report.review_id,
        "schema_version": report.schema_version,
        "review_kind": report.review_kind,
        "review_status": report.review_status,
        "finding_count": len(report.finding_reviews)
        + len(report.closure_reviews)
        + len(report.new_finding_reviews),
        "accepted_count": sum(
            item.decision == "accepted"
            for item in (*report.finding_reviews, *report.new_finding_reviews)
        ),
        "redaction_count": report.redaction_count,
        "review_ref": artifact.canonical_ref,
        "source_report_ref": report.source_report_ref,
        "target_revision": report.scope.target_revision,
        "remediation_brief": [
            item.model_dump(mode="json", exclude_none=True)
            for item in report.remediation_brief
        ],
        "artifact_ref": artifact.canonical_ref,
        "artifact_refs": [artifact.canonical_ref],
        "content": f"Published security review with status={report.review_status}",
    }
