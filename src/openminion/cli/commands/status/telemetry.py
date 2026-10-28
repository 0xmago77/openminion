from pathlib import Path
from typing import Any

from openminion.cli.parser.flags import add_json_output_flag
from openminion.cli.presentation.json_output import print_json_payload
from openminion.modules.telemetry.config import load_config
from openminion.modules.telemetry.inspection import (
    TELEMETRY_INSPECTION_EXCEPTIONS,
    build_telemetry_debug_error,
    build_telemetry_debug_report,
    open_telemetry_inspection,
    telemetry_debug_exit,
    telemetry_storage_error_code,
)
from openminion.modules.telemetry.schemas import TelemetryDebugReport
from openminion.modules.telemetry.trace.layout import resolve_trace_root


def register_telemetry_subcommand(subcommands: Any, *, handler: Any) -> None:
    parser = subcommands.add_parser(
        "telemetry",
        help="Show the latest, failed, or selected telemetry invocation",
    )
    selectors = parser.add_mutually_exclusive_group()
    selectors.add_argument(
        "--latest", action="store_true", help="Show the latest invocation (default)"
    )
    selectors.add_argument(
        "--failed", action="store_true", help="Show the latest failed invocation"
    )
    selectors.add_argument(
        "--invocation-id", help="Show one invocation by its identifier"
    )
    parser.add_argument(
        "--session-id", default="", help="Limit selection to one session"
    )
    add_json_output_flag(parser)
    parser.set_defaults(handler=handler, needs_app=False)


def run_telemetry_status(args: Any) -> int:
    selector_kind = (
        "failed"
        if bool(getattr(args, "failed", False))
        else "invocation_id"
        if getattr(args, "invocation_id", None) is not None
        else "latest"
    )
    home_root_value = str(getattr(args, "home_root", "") or "").strip()
    home_root = Path(home_root_value) if home_root_value else None
    config_path = str(getattr(args, "config", "") or "").strip() or None
    config = load_config(config_path, home_root=home_root)
    try:
        with open_telemetry_inspection(home_root=home_root) as service:
            report = build_telemetry_debug_report(
                service,
                selector_kind=selector_kind,
                invocation_id=getattr(args, "invocation_id", None),
                trace_root=resolve_trace_root(home_root=home_root),
                exporter_config=config.otel_exporter,
                session_id=str(getattr(args, "session_id", "") or "").strip() or None,
            )
    except TELEMETRY_INSPECTION_EXCEPTIONS as exc:
        report = build_telemetry_debug_error(
            telemetry_storage_error_code(exc),
            "storage",
            exporter_config=config.otel_exporter,
        )
    _render_report(
        report,
        as_json=bool(getattr(args, "json", False)),
        exact_capture_enabled=config.exact_request_traces_enabled,
    )
    return telemetry_debug_exit(report)


def _render_report(
    report: TelemetryDebugReport,
    *,
    as_json: bool,
    exact_capture_enabled: bool,
) -> None:
    if as_json:
        print_json_payload(report.to_dict())
        return
    print(f"telemetry: {report.status}")
    print(_export_health_line(report))
    print(
        "exact payload capture: " + ("enabled" if exact_capture_enabled else "disabled")
    )
    if report.error:
        print(f"error: {report.error.code}")
        print("next: telemetryctl doctor")
        return
    if report.invocation is None:
        codes = {item.code for item in report.diagnostics}
        if "NO_INVOCATIONS" in codes:
            print("No model invocations recorded yet.")
            print("next: run a model turn, then retry `openminion status telemetry`.")
            return
        if "NO_FAILED_INVOCATION" in codes:
            print("No failed model invocations found.")
            print("next: inspect the latest run with `openminion status telemetry`.")
            return
        for diagnostic in report.diagnostics:
            print(f"diagnostic: {diagnostic.code}")
        return
    invocation = report.invocation
    agent = invocation.agent_ids[0] if invocation.agent_ids else "-"
    session = invocation.session_ids[0] if invocation.session_ids else "-"
    print(
        f"invocation: {invocation.invocation_id} status={invocation.outcome} "
        f"agent={agent} session={session}"
    )
    model = (
        f"{invocation.provider}/{invocation.model}"
        if invocation.provider and invocation.model
        else "-"
    )
    usage = invocation.usage
    print(
        f"duration_ms={invocation.duration_ms if invocation.duration_ms is not None else '-'} "
        f"model={model} "
        f"tokens=input:{usage.input_tokens if usage else '-'} "
        f"output:{usage.output_tokens if usage else '-'} "
        f"cost={usage.cost_usd if usage and usage.cost_usd is not None else '-'}"
    )
    print(
        f"trace_files={invocation.trace_count if invocation.trace_count is not None else '-'}"
    )
    for command in report.links.commands:
        print(f"next: {command}")
    print("next: openminion status tokens --recent 10")


def _export_health_line(report: TelemetryDebugReport) -> str:
    health = report.export_health
    protocol = f" ({health.protocol})" if health.enabled and health.protocol else ""
    if health.enabled and health.state == "unavailable":
        return f"external export: configured{protocol}; live health unavailable"
    return f"external export: {health.state}{protocol}"


__all__ = ["register_telemetry_subcommand", "run_telemetry_status"]
