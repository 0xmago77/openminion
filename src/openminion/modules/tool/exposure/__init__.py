from typing import Any

from .contracts import (
    ToolCatalogCard,
    ToolExposureDecision,
    ToolExposureProfile,
    ToolExposureSession,
    ToolRiskAnnotations,
)
from .defaults import requires_explicit_exposure_profile
from .runtime import (
    _available_runtime_tool_names,
    get_allowed_model_tool_names,
    get_model_exposure_specs,
    get_visible_tool_specs_and_dispatch_map,
    resolve_forced_provider_tool_name,
)
from .service import ToolExposureService, exposure_scope

def render_catalog_cards(
    cards: tuple[ToolCatalogCard, ...],
    *,
    available_tool_names: set[str],
) -> str:
    """Render active profile cards that own at least one registered tool."""

    lines: list[str] = []
    for card in cards:
        tool_names = tuple(
            name for name in card.tool_names if name in available_tool_names
        )
        if not tool_names:
            continue
        lines.append(f"- {card.title} [{card.profile_id}]: {card.summary}")
        lines.append(f"  tier: {card.tier}; tools: {', '.join(tool_names)}")
        if card.target_ids:
            lines.append(f"  targets: {', '.join(card.target_ids)}")
        if card.expires_at is not None:
            lines.append(f"  expires_at: {card.expires_at:.0f}")
        if card.evidence_expectations:
            lines.append(f"  evidence: {'; '.join(card.evidence_expectations)}")
        if card.stop_rules:
            lines.append(f"  stop: {'; '.join(card.stop_rules)}")
        if card.guidance_names:
            lines.append(f"  guidance: {', '.join(card.guidance_names)}")
    if not lines:
        return ""
    return "<active_tool_profiles>\n" + "\n".join(lines) + "\n</active_tool_profiles>"


def apply_model_exposure(request: Any, registry: Any) -> None:
    """Apply model-visible tool filtering and active catalog cards."""

    metadata = getattr(request, "metadata", {}) or {}
    service = getattr(registry, "exposure_service", None)
    if request.tools:
        if isinstance(service, ToolExposureService):
            request.tools = service.filter_request_specs(
                list(request.tools),
                registered_tool_names=_available_runtime_tool_names(registry),
                allow_registered_fallback=not get_model_exposure_specs(
                    registry, metadata=metadata
                ),
                **exposure_scope(metadata),
            )
    else:
        request.tools = get_model_exposure_specs(registry, metadata=metadata)
    if not isinstance(service, ToolExposureService):
        return
    card_block = render_catalog_cards(
        service.cards(**exposure_scope(metadata)),
        available_tool_names={spec.name for spec in request.tools},
    )
    if card_block and card_block not in request.system_prompt:
        request.system_prompt = f"{request.system_prompt.rstrip()}\n\n{card_block}"


__all__ = [
    "ToolCatalogCard",
    "ToolExposureDecision",
    "ToolExposureProfile",
    "ToolExposureService",
    "ToolExposureSession",
    "ToolRiskAnnotations",
    "apply_model_exposure",
    "exposure_scope",
    "get_allowed_model_tool_names",
    "get_model_exposure_specs",
    "get_visible_tool_specs_and_dispatch_map",
    "render_catalog_cards",
    "resolve_forced_provider_tool_name",
    "requires_explicit_exposure_profile",
]
