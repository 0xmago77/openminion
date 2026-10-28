"""Evaluate two explicit AWS controls from offline snapshot facts."""

from __future__ import annotations

from typing import Any

import ipaddress
import json
from typing import Annotated, Literal

from datetime import timedelta

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from openminion.modules.tool import preferred_artifact_ref
from openminion.modules.tool.errors import ToolRuntimeError


class SnapshotRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Ipv4Range(SnapshotRecord):
    CidrIp: str


class Ipv6Range(SnapshotRecord):
    CidrIpv6: str


class IngressRule(SnapshotRecord):
    IpProtocol: str
    FromPort: int | None = Field(default=None, ge=0, le=65535)
    ToPort: int | None = Field(default=None, ge=0, le=65535)
    IpRanges: list[Ipv4Range] = Field(max_length=100)
    Ipv6Ranges: list[Ipv6Range] = Field(max_length=100)

    @model_validator(mode="after")
    def valid_networks_and_ports(self) -> IngressRule:
        if self.IpProtocol in {"tcp", "6"} and (
            self.FromPort is None or self.ToPort is None or self.FromPort > self.ToPort
        ):
            raise ValueError("TCP requires an ordered port range")
        if self.IpProtocol not in {"tcp", "udp", "icmp", "icmpv6", "-1"} and not (
            self.IpProtocol.isdecimal() and 0 <= int(self.IpProtocol) <= 255
        ):
            raise ValueError("Invalid IP protocol")
        if len(self.IpRanges) + len(self.Ipv6Ranges) > 100:
            raise ValueError("At most 100 CIDRs per permission")
        for value in self.IpRanges:
            ipaddress.IPv4Network(value.CidrIp)
        for ipv6 in self.Ipv6Ranges:
            ipaddress.IPv6Network(ipv6.CidrIpv6)
        return self


class SecurityGroup(SnapshotRecord):
    GroupId: str = Field(min_length=1, max_length=100)
    IpPermissions: list[IngressRule] = Field(max_length=100)


class Volume(SnapshotRecord):
    VolumeId: str = Field(min_length=1, max_length=100)
    Encrypted: bool


class CollectionError(SnapshotRecord):
    resource_id: str = Field(min_length=1, max_length=100)
    code: str = Field(min_length=1, max_length=100)


class AwsSnapshot(SnapshotRecord):
    schema_version: Literal["aws-security-snapshot/v1"]
    source: Literal["fixture", "operator_snapshot"]
    expected_account_id: str = Field(pattern=r"^[0-9]{12}$")
    caller_account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(min_length=1, max_length=100)
    captured_at: AwareDatetime
    requested_group_ids: list[Annotated[str, Field(min_length=1, max_length=100)]] = (
        Field(max_length=100)
    )
    requested_volume_ids: list[Annotated[str, Field(min_length=1, max_length=100)]] = (
        Field(max_length=100)
    )
    security_groups: list[SecurityGroup] = Field(max_length=100)
    volumes: list[Volume] = Field(max_length=100)
    collection_errors: list[CollectionError] = Field(max_length=20)
    pagination_remaining: bool

    @model_validator(mode="after")
    def scoped_records(self) -> Any:
        if self.captured_at.utcoffset() != timedelta(0):
            raise ValueError("Snapshot timestamp must be UTC")
        if self.expected_account_id != self.caller_account_id:
            raise ValueError("Snapshot account mismatch")
        requested = self.requested_group_ids + self.requested_volume_ids
        if not requested or len(requested) != len(set(requested)):
            raise ValueError("Requested resource IDs must be nonempty and unique")
        for ids, records in (
            (
                self.requested_group_ids,
                [group.GroupId for group in self.security_groups],
            ),
            (self.requested_volume_ids, [volume.VolumeId for volume in self.volumes]),
        ):
            if len(records) != len(set(records)) or not set(records).issubset(ids):
                raise ValueError("Duplicate or unrequested resource record")
        if any(error.resource_id not in requested for error in self.collection_errors):
            raise ValueError("Collection error names an unrequested resource")
        return self


class AwsSnapshotArgs(SnapshotRecord):
    input_ref: str = Field(pattern=r"^artifact://sha256/[0-9a-f]{64}$")


class SnapshotCandidate(SnapshotRecord):
    control_id: Literal["administrative-ingress", "unencrypted-volume"]
    resource_id: str
    observed: dict[str, Any]


class SnapshotCoverage(SnapshotRecord):
    requested: int = Field(ge=1, le=200)
    observed: int = Field(ge=0, le=200)


class SnapshotAssessment(SnapshotRecord):
    schema_version: Literal["aws-security-assessment/v1"]
    source: Literal["fixture", "operator_snapshot"]
    input_ref: str
    account_id: str
    region: str
    captured_at: str
    status: Literal["completed", "partial", "failed"]
    review_status: Literal["unreviewed"]
    coverage: SnapshotCoverage
    candidates: list[SnapshotCandidate]
    limitations: str


def evaluate(snapshot: AwsSnapshot, input_ref: str) -> dict[str, Any]:
    candidates = []
    for group in snapshot.security_groups:
        for rule in group.IpPermissions:
            administrative = rule.IpProtocol == "-1" or (
                rule.IpProtocol in {"tcp", "6"}
                and rule.FromPort is not None
                and rule.ToPort is not None
                and any(rule.FromPort <= port <= rule.ToPort for port in (22, 3389))
            )
            world = any(
                ipaddress.ip_network(row.CidrIp).prefixlen == 0 for row in rule.IpRanges
            ) or any(
                ipaddress.ip_network(row.CidrIpv6).prefixlen == 0
                for row in rule.Ipv6Ranges
            )
            if administrative and world:
                candidates.append(
                    {
                        "control_id": "administrative-ingress",
                        "resource_id": group.GroupId,
                        "observed": rule.model_dump(),
                    }
                )
    for volume in snapshot.volumes:
        if not volume.Encrypted:
            candidates.append(
                {
                    "control_id": "unencrypted-volume",
                    "resource_id": volume.VolumeId,
                    "observed": volume.model_dump(),
                }
            )
    requested = len(snapshot.requested_group_ids) + len(snapshot.requested_volume_ids)
    observed = len(snapshot.security_groups) + len(snapshot.volumes)
    partial = bool(
        requested != observed
        or snapshot.collection_errors
        or snapshot.pagination_remaining
    )
    return {
        "schema_version": "aws-security-assessment/v1",
        "source": snapshot.source,
        "input_ref": input_ref,
        "account_id": snapshot.caller_account_id,
        "region": snapshot.region,
        "captured_at": snapshot.captured_at.isoformat(),
        "status": "partial" if partial else "completed",
        "review_status": "unreviewed",
        "coverage": {"requested": requested, "observed": observed},
        "candidates": candidates,
        "limitations": "Offline supplied facts; no live account collection or reachability proof.",
    }


def evaluate_snapshot_handler(args: Any, ctx: Any) -> dict[str, Any]:
    parsed = AwsSnapshotArgs.model_validate(args)
    if ctx.permission_mode != "readonly":
        raise ToolRuntimeError(
            "POLICY_DENIED", "Snapshot evaluation requires readonly mode"
        )
    stored = ctx.artifactctl.get(parsed.input_ref)
    if stored.session_id != ctx.session_id or stored.size_bytes > 1_048_576:
        raise ToolRuntimeError("POLICY_DENIED", "Snapshot access or size limit failed")
    snapshot = AwsSnapshot.model_validate_json(
        ctx.artifactctl.read_bytes(parsed.input_ref)
    )
    result = SnapshotAssessment.model_validate(
        evaluate(snapshot, parsed.input_ref)
    ).model_dump()
    ref = preferred_artifact_ref(
        ctx.write_artifact(
            "security/aws-snapshot.json",
            json.dumps(result, sort_keys=True).encode(),
            "application/json",
            durable=True,
        )
    )
    return {"ok": True, **result, "artifact_ref": ref, "artifact_refs": [ref]}
