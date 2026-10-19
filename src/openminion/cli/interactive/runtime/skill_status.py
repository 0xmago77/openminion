from __future__ import annotations

from pathlib import Path
from typing import Any

from openminion.modules.skill import Skill
from openminion.modules.skill.learning import WorkflowShapeMiner
from openminion.modules.skill.learning.runtime import WorkflowObservationError
from openminion.modules.skill.suggestion import suggestion_status


def skill_learning_summary(
    *, config_path: Any, home_root: Path, agent_id: str
) -> list[str]:
    skill = Skill(config_path or {}, home_root=home_root)
    try:
        try:
            observations = skill.list_workflow_observations(agent_id=agent_id)
            shapes = skill.list_workflow_shapes(agent_id=agent_id)
        except WorkflowObservationError as exc:
            return ["Learning:", f"  unavailable         {exc}"]
        miner = WorkflowShapeMiner()
        ready_count = sum(miner.is_skill_ready(shape) for shape in shapes)
        pending_count = suggestion_status(skill.store).pending_count
    finally:
        skill.close()
    if not ready_count and not pending_count:
        return []
    return [
        "Learning:",
        f"  observations       {len(observations)} · active agent",
        f"  authoring ready    {ready_count} · active agent",
        f"  pending proposals  {pending_count} · catalog-wide",
    ]


__all__ = ["skill_learning_summary"]
