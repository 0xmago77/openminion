"""Argument parser for MCP management commands."""

from __future__ import annotations

import argparse
import json

from openminion.base.config.mcp import MCPToolRiskOverrideConfig


def _key_value_argument(value: str) -> tuple[str, str]:
    key, separator, item_value = value.partition("=")
    key = key.strip()
    item_value = item_value.strip()
    if not separator or not key or not item_value:
        raise argparse.ArgumentTypeError("expected KEY=VALUE with non-empty values")
    return key, item_value


def _risk_override_argument(value: str) -> MCPToolRiskOverrideConfig:
    from openminion.base.config.base import ConfigError
    from openminion.base.config.mcp import MCPToolRiskOverrideConfig

    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid JSON risk override: {exc.msg}"
        ) from exc
    if not isinstance(payload, dict):
        raise argparse.ArgumentTypeError("risk override must be a JSON object")
    try:
        return MCPToolRiskOverrideConfig(**payload)
    except (ConfigError, TypeError) as exc:
        raise argparse.ArgumentTypeError(f"invalid risk override: {exc}") from exc


def _register_add_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    handler: object,
) -> None:
    parser = subparsers.add_parser("add", help="Add an MCP server", allow_abbrev=False)
    parser.add_argument("name", help="Server name")
    parser.add_argument("--url", default="", help="Streamable HTTP endpoint")
    parser.add_argument("--cwd", default="", help="stdio working directory")
    parser.add_argument(
        "--startup-timeout", type=float, default=15.0, help="Startup timeout in seconds"
    )
    parser.add_argument(
        "--request-timeout", type=float, default=30.0, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--stderr-buffer-bytes",
        type=int,
        default=65536,
        help="Maximum captured stderr bytes",
    )
    parser.add_argument(
        "--env",
        action="append",
        type=_key_value_argument,
        default=[],
        metavar="KEY=VALUE",
    )
    parser.add_argument(
        "--env-secret",
        action="append",
        type=_key_value_argument,
        default=[],
        metavar="KEY=SECRET_REF",
    )
    parser.add_argument(
        "--auth", choices=("none", "bearer", "oauth-pkce"), default="none"
    )
    for name in (
        "bearer-token-ref",
        "client-id",
        "client-issuer",
        "authorization-metadata-url",
        "authorization-endpoint",
        "token-endpoint",
        "registration-endpoint",
        "revocation-endpoint",
        "redirect-uri",
        "scope",
        "access-token-ref",
        "refresh-token-ref",
    ):
        parser.add_argument(f"--{name}", default="")
    parser.add_argument(
        "--approval-mode",
        choices=("never", "always", "dangerous", "matching"),
        default="never",
    )
    parser.add_argument("--approval-tool", action="append", default=[])
    parser.add_argument(
        "--approval-risk",
        choices=("low", "medium", "high"),
        action="append",
        default=[],
    )
    parser.add_argument(
        "--sandbox-require-trust", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument("--sandbox-cwd", action="append", default=[])
    parser.add_argument("--sandbox-env", action="append", default=[])
    parser.add_argument("--sandbox-inherit-env", action="append", default=[])
    parser.add_argument("--sandbox-package-name", default="")
    parser.add_argument("--sandbox-package-version", default="")
    parser.add_argument("--sandbox-trust-reason", default="")
    parser.add_argument(
        "--risk-override",
        action="append",
        type=_risk_override_argument,
        default=[],
        metavar="JSON",
    )
    parser.add_argument("--trusted", action="store_true", help="Trust stdio server")
    parser.add_argument(
        "--required", action="store_true", help="Require server discovery at startup"
    )
    parser.add_argument("--disabled", action="store_true", help="Add without enabling")
    parser.add_argument(
        "--command",
        nargs=argparse.REMAINDER,
        default=[],
        help="stdio command after --",
    )
    parser.set_defaults(handler=handler)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    handler: object,
) -> None:
    parser = subparsers.add_parser("mcp", help="Manage MCP servers")
    mcp_sub = parser.add_subparsers(dest="mcp_command", required=True)
    _register_add_parser(mcp_sub, handler)

    for command, help_text in (
        ("get", "Show one configured MCP server"),
        ("remove", "Remove an MCP server"),
        ("enable", "Enable an MCP server"),
        ("disable", "Disable an MCP server"),
        ("trust", "Trust a local stdio MCP server"),
        ("untrust", "Revoke trust from a local stdio MCP server"),
    ):
        lifecycle_parser = mcp_sub.add_parser(command, help=help_text)
        lifecycle_parser.add_argument("name", help="Server name")
        lifecycle_parser.set_defaults(handler=handler)

    import_parser = mcp_sub.add_parser("import", help="Import MCP server config")
    import_parser.add_argument(
        "--from", dest="source", required=True, help="Source JSON file"
    )
    import_parser.add_argument(
        "--write",
        action="store_true",
        help="Write imported servers to OpenMinion config",
    )
    import_parser.set_defaults(handler=handler)

    list_parser = mcp_sub.add_parser("list", help="List configured MCP servers")
    list_parser.set_defaults(handler=handler)

    validate_parser = mcp_sub.add_parser("validate", help="Validate MCP server config")
    validate_parser.set_defaults(handler=handler)

    test_parser = mcp_sub.add_parser("test", help="Test MCP server discovery")
    test_parser.add_argument("name", nargs="?", default="", help="Optional server name")
    test_parser.set_defaults(handler=handler)

    login_parser = mcp_sub.add_parser("login", help="Authorize a remote MCP server")
    login_parser.add_argument("name", help="Configured MCP server name")
    login_parser.add_argument("--code", default="", help="Authorization code")
    login_parser.add_argument("--issuer", default="", help="Authorization issuer")
    login_parser.add_argument(
        "--manual",
        action="store_true",
        help="Print the authorization URL instead of opening a loopback callback",
    )
    login_parser.add_argument(
        "--callback-timeout",
        type=float,
        default=180.0,
        help="Loopback callback timeout in seconds",
    )
    login_parser.add_argument(
        "--state",
        default="",
        help="State returned with the authorization response",
    )
    login_parser.set_defaults(handler=handler)

    browse_parser = mcp_sub.add_parser("browse", help="List server capabilities")
    browse_parser.add_argument("name", nargs="?", default="", help="Server name")
    browse_parser.set_defaults(handler=handler)

    prompt_parser = mcp_sub.add_parser("prompt", help="Get an MCP prompt")
    prompt_parser.add_argument("name", help="Server name")
    prompt_parser.add_argument("prompt_name", help="Prompt name")
    prompt_parser.add_argument("--arguments", default="{}", help="JSON arguments")
    prompt_parser.set_defaults(handler=handler)

    resource_parser = mcp_sub.add_parser("resource", help="Read an MCP resource")
    resource_parser.add_argument("name", help="Server name")
    resource_parser.add_argument("uri", help="Resource URI")
    resource_parser.set_defaults(handler=handler)

    registry_parser = mcp_sub.add_parser(
        "registry-search", help="Search the official MCP registry"
    )
    registry_parser.add_argument("query", help="Server-name search query")
    registry_parser.add_argument("--limit", type=int, choices=range(1, 101), default=20)
    registry_parser.set_defaults(handler=handler)

    serve_parser = mcp_sub.add_parser("serve", help="Publish tools over MCP stdio")
    serve_parser.set_defaults(handler=handler)


__all__ = ["register"]
