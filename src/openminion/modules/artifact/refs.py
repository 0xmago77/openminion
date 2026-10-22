from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from openminion.modules.artifact.interfaces import ArtifactReferenceLifecycle
from openminion.modules.artifact.models import parse_ref_or_sha

if TYPE_CHECKING:
    from openminion.modules.artifact.config import ArtifactCtlConfig


def normalize_artifact_ref_target(value: Any) -> str | None:
    """Return a valid artifact ref target or ``None`` for non-artifact evidence."""
    mime = (
        value.get("mime")
        if isinstance(value, Mapping)
        else getattr(value, "mime", None)
    )
    if str(mime or "").strip() == "application/x-openminion-capture":
        return None
    candidates: list[Any] = []
    if isinstance(value, (str, bytes)):
        candidates.append(value.decode() if isinstance(value, bytes) else value)
    elif isinstance(value, Mapping):
        candidates.extend((value.get("ref"), value.get("sha256")))
    else:
        ref_value = getattr(value, "ref", None)
        sha_value = getattr(value, "sha256", None)
        if ref_value is not None or sha_value is not None:
            candidates.extend((ref_value, sha_value))
        else:
            candidates.append(value)

    for candidate in candidates:
        text = str(candidate or "").strip()
        if not text:
            continue
        try:
            return parse_ref_or_sha(text)
        except ValueError:
            continue
    return None


def normalize_artifact_ref_targets(values: Any) -> list[str]:
    """Normalize a heterogeneous artifact ref payload into unique valid targets."""
    if values is None:
        return []
    if isinstance(values, (str, bytes, Mapping)):
        raw_values = [values]
    else:
        try:
            raw_values = list(values)
        except TypeError:
            raw_values = [values]

    targets: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        target = normalize_artifact_ref_target(value)
        if target is None or target in seen:
            continue
        seen.add(target)
        targets.append(target)
    return targets


def create_default_artifactctl(config: "ArtifactCtlConfig | None" = None) -> Any:
    from openminion.modules.artifact.control import ArtifactCtl

    return ArtifactCtl({} if config is None else config)


def add_reference_edges(
    *,
    artifactctl: ArtifactReferenceLifecycle | None,
    owner_type: str,
    owner_id: str,
    ref_values: Any,
) -> None:
    if artifactctl is None:
        return
    for target in normalize_artifact_ref_targets(ref_values):
        artifactctl.ref_add(owner_type, owner_id, target)


def remove_reference_edges(
    *,
    artifactctl: ArtifactReferenceLifecycle | None,
    owner_type: str,
    owner_id: str,
    ref_values: Any,
) -> None:
    if artifactctl is None:
        return
    for target in normalize_artifact_ref_targets(ref_values):
        artifactctl.ref_remove(owner_type, owner_id, target)


def remove_owner_reference_edges(
    *,
    artifactctl: ArtifactReferenceLifecycle | None,
    owner_type: str,
    owner_id: str,
) -> None:
    if artifactctl is not None:
        artifactctl.ref_remove_owner(owner_type, owner_id)
