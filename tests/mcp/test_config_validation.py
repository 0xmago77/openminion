from __future__ import annotations

import re

import pytest

from openminion.base.config.base import ConfigError
from openminion.base.config.mcp import (
    coerce_mcp_exposure_config,
    coerce_mcp_publish_config,
    coerce_mcp_server_configs,
)


@pytest.mark.parametrize(
    ("override", "field_path"),
    [
        ({"command": "python server.py"}, "runtime.mcp_servers[].command"),
        (
            {"tool_risk_overrides": "delete-*"},
            "runtime.mcp_servers[].tool_risk_overrides",
        ),
        (
            {"approval": {"tool_patterns": "delete-*"}},
            "runtime.mcp_servers[].approval.tool_patterns",
        ),
        (
            {"approval": {"risk_levels": "high"}},
            "runtime.mcp_servers[].approval.risk_levels",
        ),
        (
            {"stdio_sandbox": {"cwd_allowlist": "/safe"}},
            "runtime.mcp_servers[].stdio_sandbox.cwd_allowlist",
        ),
        (
            {"stdio_sandbox": {"env_allowlist": "TOKEN"}},
            "runtime.mcp_servers[].stdio_sandbox.env_allowlist",
        ),
        (
            {"stdio_sandbox": {"inherit_env_allowlist": "PATH"}},
            "runtime.mcp_servers[].stdio_sandbox.inherit_env_allowlist",
        ),
        (
            {"package_metadata": {"install_command": "npm install fixture"}},
            "runtime.mcp_servers[].package_metadata.install_command",
        ),
    ],
)
def test_mcp_server_config_rejects_non_list_fields(
    override: dict[str, object], field_path: str
) -> None:
    payload: dict[str, object] = {
        "name": "fixture",
        "command": ["python", "server.py"],
        **override,
    }

    with pytest.raises(ConfigError, match=re.escape(field_path)):
        coerce_mcp_server_configs([payload])


@pytest.mark.parametrize(
    ("override", "field_path"),
    [
        (
            {"tool_risk_overrides": [{"pattern": "*", "dangerous": "false"}]},
            "runtime.mcp_servers[].tool_risk_overrides[].dangerous",
        ),
        (
            {"tool_risk_overrides": [{"pattern": "*", "idempotent": 0}]},
            "runtime.mcp_servers[].tool_risk_overrides[].idempotent",
        ),
        (
            {"stdio_sandbox": {"require_trust": "false"}},
            "runtime.mcp_servers[].stdio_sandbox.require_trust",
        ),
    ],
)
def test_mcp_server_config_rejects_non_boolean_fields(
    override: dict[str, object], field_path: str
) -> None:
    payload: dict[str, object] = {
        "name": "fixture",
        "command": ["python", "server.py"],
        **override,
    }

    with pytest.raises(ConfigError, match=re.escape(field_path)):
        coerce_mcp_server_configs([payload])


@pytest.mark.parametrize(
    "field_name",
    ("include_servers", "exclude_servers", "include_tools", "exclude_tools"),
)
def test_mcp_exposure_rejects_non_list_fields(field_name: str) -> None:
    field_path = f"agents.<id>.mcp_exposure.{field_name}"

    with pytest.raises(ConfigError, match=re.escape(field_path)):
        coerce_mcp_exposure_config({field_name: "mcp.fixture.*"})


@pytest.mark.parametrize("field_name", ("include_tools", "exclude_tools"))
def test_mcp_publish_rejects_non_list_fields(field_name: str) -> None:
    field_path = f"runtime.mcp_publish.{field_name}"

    with pytest.raises(ConfigError, match=re.escape(field_path)):
        coerce_mcp_publish_config({field_name: "file.*"})


def test_mcp_publish_rejects_non_boolean_enabled() -> None:
    with pytest.raises(ConfigError, match="runtime.mcp_publish.enabled"):
        coerce_mcp_publish_config({"enabled": "false"})


def test_mcp_list_fields_reject_null_and_non_string_items() -> None:
    with pytest.raises(ConfigError, match="runtime.mcp_publish.include_tools"):
        coerce_mcp_publish_config({"include_tools": None})
    with pytest.raises(ConfigError, match=r"runtime.mcp_publish.exclude_tools\[0\]"):
        coerce_mcp_publish_config({"exclude_tools": [1]})
