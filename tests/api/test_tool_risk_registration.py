"""Declared risk ownership and temporary SDK registration lifetimes."""

import pytest

from openminion import Agent, Handoff, tool
from openminion.modules.policy.models import RiskSpec
from openminion.modules.policy.runtime.service import PolicyCtl
from openminion.modules.tool.errors import ToolRuntimeError
from tests.api.test_handoff import _FakeRuntime
from openminion.modules.tool.registry import ToolRegistry


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("existing_risk", [False, True])
@pytest.mark.parametrize("read_name", ["format_report", "format.report"])
def test_temporary_risks_match_tool_and_profile_lifetime(
    failure, existing_risk, read_name
):
    policy = PolicyCtl.with_sqlite(":memory:")

    @tool(name=read_name, min_scope="READ_ONLY", idempotent=True)
    def report(order_id: str) -> str:
        return order_id

    class Runtime(_FakeRuntime):
        def run_turn(self, *, payload, **kwargs):
            assert set(self.tools.list()) == {read_name, "transfer_to_child"}
            assert len(self.tools.exposure_service.profiles) == 2
            expected_keys = {
                read_name,
                "transfer_to_child",
                "transfer_to_child.default",
            }
            if read_name == "format_report":
                expected_keys.add("format_report.default")
            assert set(policy._risk_registry) == set(before) | expected_keys
            if read_name == "format.report" and existing_risk:
                assert (
                    policy._risk_registry["format.report.default"]
                    == before["format.report.default"]
                )
            read = policy.check(
                {"tool": "format", "method": "report"}
                if "." in read_name
                else {"tool": read_name, "method": "default"},
                {},
            )
            assert read.decision == "ALLOW"
            assert read.risk.to_dict() == {
                "risk_class": "read",
                "side_effects": "none",
                "reversibility": "reversible",
                "default_confirm": False,
                "sensitive_targets": [],
            }
            handoff = policy.check(
                {"tool": "transfer_to_child", "method": "default"}, {}
            )
            assert handoff.risk.to_dict() == {
                "risk_class": "write",
                "side_effects": "local",
                "reversibility": "unknown",
                "default_confirm": True,
                "sensitive_targets": [],
            }
            assert handoff.decision == "REQUIRE_CONFIRM"
            if failure:
                raise RuntimeError("turn failed")
            return {"body": "runtime result"}

    runtime = Runtime(tools=ToolRegistry(), action_policy=policy)
    if existing_risk:
        for name in (read_name, f"{read_name}.default", "transfer_to_child.default"):
            policy.register_risk(name, RiskSpec(risk_class="security"))
    before = dict(policy._risk_registry)
    child = Agent(runtime=runtime, tools=[], name="child")
    parent = Agent(runtime=runtime, tools=[report], handoffs=[Handoff(target=child)])
    try:
        if failure:
            with pytest.raises(RuntimeError, match="turn failed"):
                parent.run("delegate")
        else:
            assert parent.run("delegate").text == "runtime result"
    finally:
        assert runtime.tools.list() == {}
        assert runtime.tools.exposure_service.profiles == ()
        assert policy._risk_registry == before
        policy.close()


def test_registration_failure_rolls_back_tools_profiles_and_preserves_risks():
    policy = PolicyCtl.with_sqlite(":memory:")
    registry = ToolRegistry()

    @tool(name="format_report", min_scope="READ_ONLY", idempotent=True)
    def first(order_id: str) -> str:
        return order_id

    @tool(name="format_report", dangerous=True)
    def duplicate(order_id: str) -> str:
        return order_id

    runtime = _FakeRuntime(tools=registry, action_policy=policy)
    policy.register_risk("format_report.default", RiskSpec(risk_class="financial"))
    before = dict(policy._risk_registry)
    try:
        with pytest.raises(ToolRuntimeError, match="already registered"):
            Agent(runtime=runtime, tools=[first, duplicate]).run("report")
        assert registry.list() == {}
        assert registry.exposure_service.profiles == ()
        assert policy._risk_registry == before
    finally:
        policy.close()


@pytest.mark.parametrize(
    ("name", "args", "risk", "decision"),
    [
        ("unknown.get", {}, "read", "ALLOW"),
        ("unknown.get_remove", {}, "read", "ALLOW"),
        ("unknown.remove", {}, "destructive", "REQUIRE_CONFIRM"),
        ("transfer_to_unknown", {}, "financial", "REQUIRE_CONFIRM"),
        ("unknown.exec", {}, "exec", "REQUIRE_CONFIRM"),
        ("unknown.ssh", {}, "exec", "REQUIRE_CONFIRM"),
        ("unknown.update", {}, "state_change", "REQUIRE_CONFIRM"),
        ("browser.click", {}, "state_change", "REQUIRE_CONFIRM"),
        ("unknown", {"path": "report.txt"}, "write", "REQUIRE_CONFIRM"),
        ("unknown", {"content": "report"}, "write", "REQUIRE_CONFIRM"),
        ("unknown", {}, "read", "ALLOW"),
    ],
)
def test_undeclared_tools_keep_fallback_risk(name, args, risk, decision):
    policy = PolicyCtl.with_sqlite(":memory:")
    try:
        tool_name, _, method = name.rpartition(".")
        result = policy.check(
            {
                "tool": tool_name or name,
                "method": method if tool_name else "default",
                "args": args,
            },
            {},
        )
        assert (result.risk.risk_class, result.decision) == (risk, decision)
        if name.endswith("ssh"):
            assert result.risk.side_effects == "remote"
        if name == "browser.click":
            assert result.risk.side_effects == "external_account"
    finally:
        policy.close()
