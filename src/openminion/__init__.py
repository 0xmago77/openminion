"""OpenMinion's stable package-level public API."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from .base.version import OPENMINION_VERSION
from .base.version import PROVIDER_ERROR_PUBLIC_VERSION
from .base.version import TURN_TIMEOUT_ERROR_PUBLIC_VERSION

if TYPE_CHECKING:
    from .api import APIRuntime as APIRuntime, Agent as Agent
    from .api import AgentOutputValidationError as AgentOutputValidationError
    from .api import TurnTimeoutError as TurnTimeoutError
    from .api import AgentRunResult as AgentRunResult, Handoff as Handoff
    from .api import ProviderError as ProviderError, subagent as subagent
    from .base.config import OpenMinionConfig as OpenMinionConfig
    from .modules.memory.portability import MemoryBundle as MemoryBundle
    from .tools import tool as tool

__version__ = OPENMINION_VERSION
_LAZY_EXPORTS = {
    "APIRuntime": ("openminion.api", "APIRuntime"),
    "Agent": ("openminion.api", "Agent"),
    "AgentOutputValidationError": ("openminion.api", "AgentOutputValidationError"),
    "AgentRunResult": ("openminion.api", "AgentRunResult"),
    "Handoff": ("openminion.api", "Handoff"),
    "MemoryBundle": ("openminion.modules.memory.portability", "MemoryBundle"),
    "OpenMinionConfig": ("openminion.base.config", "OpenMinionConfig"),
    "ProviderError": ("openminion.modules.llm", "ProviderError"),
    "TurnTimeoutError": ("openminion.api.turns", "TurnTimeoutError"),
    "subagent": ("openminion.api", "subagent"),
    "tool": ("openminion.tools", "tool"),
}
__all__ = [*_LAZY_EXPORTS, "__version__"]
__since__ = dict.fromkeys(_LAZY_EXPORTS.keys() | {"__version__"}, "0.0.1")
__since__["ProviderError"] = PROVIDER_ERROR_PUBLIC_VERSION
__since__["TurnTimeoutError"] = TURN_TIMEOUT_ERROR_PUBLIC_VERSION


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute_name = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module 'openminion' has no attribute {name!r}") from exc

    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value
