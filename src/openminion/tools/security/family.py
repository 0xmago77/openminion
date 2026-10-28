"""Declarative security scanner family and exposure profile."""

from openminion.modules.tool.exposure import ToolExposureProfile, ToolRiskAnnotations
from openminion.modules.tool.framework import ToolDecl, ToolFamilySpec

from .interfaces import (
    READONLY_SECURITY_TOOLS,
    OFFLINE_SECURITY_TOOLS,
    DERIVED_SECURITY_TOOLS,
    TOOL_SECURITY_EVALUATE_AWS_SNAPSHOT,
    TOOL_SECURITY_EXPORT_SARIF,
    TOOL_SECURITY_COMPARE_SCANS,
    TOOL_SECURITY_SCAN_SNAPSHOT,
    TOOL_SECURITY_SCAN_IMAGE,
    TOOL_SECURITY_REVIEW_REPORT,
    TOOL_SECURITY_PUBLISH_REPORT,
    TOOL_SECURITY_SCAN_ARTIFACT,
    TOOL_SECURITY_SCAN_CODE,
    TOOL_SECURITY_SCAN_DEPENDENCIES,
    TOOL_SECURITY_SCAN_SECRETS,
)
from .dependencies import SEMGREP_DEPENDENCY, TRIVY_DEPENDENCY
from .plugin import (
    _h_scan_artifact,
    _h_scan_code,
    _h_scan_dependencies,
    _h_scan_secrets,
    _h_publish_report,
    _h_review_report,
)
from .archive_schemas import ArchiveScanArgs, SnapshotScanArgs
from .schemas import (
    LocalScanArgs,
    SecurityReportPublishArgs,
)
from .offline import scan_image_handler, scan_snapshot_handler
from .review_schemas import SecurityReviewArgs

from .aws_snapshot import AwsSnapshotArgs, evaluate_snapshot_handler
from .derived import (
    ExportSarifArgs,
    CompareScansArgs,
    export_sarif_handler,
    compare_scans_handler,
)

SECURITY_FAMILY = ToolFamilySpec(
    module_id="security",
    min_scope_default="READ_ONLY",
    common_tags=("plugin", "security", "read_only"),
    common_capabilities=("read_only", "security", "evidence"),
    exposure_profiles=(
        ToolExposureProfile(
            profile_id="security_reporting",
            title="Security evidence",
            summary="Offline AWS snapshots, SARIF export and exact scan comparison.",
            tool_names=frozenset(DERIVED_SECURITY_TOOLS),
            evidence_expectations=("preserve source references and completeness",),
            stop_rules=("do not infer resolution from absence",),
        ),
        ToolExposureProfile(
            profile_id="security_offline",
            title="Isolated security scanning",
            summary="Offline scans of approved source and image archives.",
            tool_names=frozenset(OFFLINE_SECURITY_TOOLS),
            evidence_expectations=(
                "return immutable scanner evidence and isolation facts",
            ),
            stop_rules=("stop if offline isolation is unavailable",),
            activation_hint="Configure a pinned local worker and approved archive targets.",
        ),
        ToolExposureProfile(
            profile_id="security_review",
            title="Independent security review",
            summary="Review complete source-security reports without modifying source.",
            tool_names=frozenset({TOOL_SECURITY_REVIEW_REPORT}),
            evidence_expectations=("return an immutable canonical review reference",),
            stop_rules=("stop before remediation or scanner execution",),
            activation_hint="Activate for a distinct readonly reviewer with complete evidence.",
        ),
        ToolExposureProfile(
            profile_id="security_readonly",
            title="Security scanning",
            summary="Bounded local source, dependency, IaC, and secret scans.",
            tool_names=frozenset(READONLY_SECURITY_TOOLS),
            evidence_expectations=(
                "return scanner identity, version, bounded findings, and evidence refs",
            ),
            stop_rules=("stop before remediation, network update, or remote scanning",),
            activation_hint="Activate for an approved local read-only security audit.",
        ),
        ToolExposureProfile(
            profile_id="security_lab",
            title="Authorized local security lab",
            summary="Evidence-backed active validation of one configured local target.",
            tool_names=frozenset({TOOL_SECURITY_PUBLISH_REPORT}),
            risk=ToolRiskAnnotations(
                tier="apply",
                requires_approval=True,
                mutates_state=False,
            ),
            target_kinds=frozenset({"local_docker"}),
            evidence_expectations=("return canonical exec evidence",),
            stop_rules=("stop before remediation or off-target access",),
            activation_hint="Approve one configured local Docker target for this session.",
        ),
    ),
    tools=(
        ToolDecl(
            TOOL_SECURITY_EVALUATE_AWS_SNAPSHOT,
            AwsSnapshotArgs,
            evaluate_snapshot_handler,
            "Evaluate two AWS controls from supplied offline snapshot facts.",
            idempotent=True,
        ),
        ToolDecl(
            TOOL_SECURITY_EXPORT_SARIF,
            ExportSarifArgs,
            export_sarif_handler,
            "Export canonical source scan evidence as SARIF 2.1.0.",
            idempotent=True,
        ),
        ToolDecl(
            TOOL_SECURITY_COMPARE_SCANS,
            CompareScansArgs,
            compare_scans_handler,
            "Compare exact IDs from compatible complete scans without claiming resolution.",
            idempotent=True,
        ),
        ToolDecl(
            TOOL_SECURITY_SCAN_SNAPSHOT,
            SnapshotScanArgs,
            scan_snapshot_handler,
            "Scan an approved source tar inside an offline worker.",
            idempotent=True,
        ),
        ToolDecl(
            TOOL_SECURITY_SCAN_IMAGE,
            ArchiveScanArgs,
            scan_image_handler,
            "Scan one approved Docker-save image archive offline.",
            idempotent=True,
        ),
        ToolDecl(
            TOOL_SECURITY_REVIEW_REPORT,
            SecurityReviewArgs,
            _h_review_report,
            "Record independent finding decisions or fresh-revision follow-up review.",
        ),
        ToolDecl(
            TOOL_SECURITY_SCAN_CODE,
            LocalScanArgs,
            _h_scan_code,
            "Scan approved local source with configured Semgrep rules.",
            idempotent=True,
            dependencies=(SEMGREP_DEPENDENCY,),
        ),
        ToolDecl(
            TOOL_SECURITY_SCAN_DEPENDENCIES,
            LocalScanArgs,
            _h_scan_dependencies,
            "Scan approved local dependency manifests with Trivy.",
            idempotent=True,
            dependencies=(TRIVY_DEPENDENCY,),
        ),
        ToolDecl(
            TOOL_SECURITY_SCAN_ARTIFACT,
            LocalScanArgs,
            _h_scan_artifact,
            "Scan approved local filesystem or IaC artifacts with Trivy.",
            idempotent=True,
            dependencies=(TRIVY_DEPENDENCY,),
        ),
        ToolDecl(
            TOOL_SECURITY_SCAN_SECRETS,
            LocalScanArgs,
            _h_scan_secrets,
            "Scan approved local files for secret findings with Trivy.",
            idempotent=True,
            dependencies=(TRIVY_DEPENDENCY,),
        ),
        ToolDecl(
            TOOL_SECURITY_PUBLISH_REPORT,
            SecurityReportPublishArgs,
            _h_publish_report,
            "Publish one canonical unreviewed candidate security-audit report.",
        ),
    ),
)

__all__ = ["SECURITY_FAMILY"]
