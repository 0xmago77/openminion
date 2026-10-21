"""Security lifecycle mechanics with real Git/CAS/verifier and scripted model decisions."""

import json
import hashlib
import sys
from pathlib import Path

import pytest

from openminion.cli.commands.autonomy_project import (
    build_project_launch_request,
    launch_project,
)
from openminion.modules.brain.adapters.tool import ToolAdapter
from openminion.modules.brain.execution.worktree_children import (
    load_child_worktree_record,
)
from openminion.modules.task import AutonomyRunStatus, AutonomyRunStore, TaskManager
from openminion.modules.task.project.models import ProjectCheckpoint
from openminion.modules.task.project.verification import (
    run_project_verification_commands,
)
from openminion.modules.telemetry.trace.metadata import structural_tool_payload
from openminion.modules.tool.runtime.delegation import A2ADelegateResult
from openminion.services.runtime.project_worker import ProjectWorker, ProjectTurnResult
from openminion.tools.security.plugin import (
    _h_publish_report,
    _h_review_report,
    _h_scan_code,
)
from tests.tools.security.test_audit_report import (
    audit_context as audit_context,
    _git,
    _publish_args,
    _scan,
    _store_scan,
)
from tests.tools.security.test_review_report import (
    _decision,
    _initial,
    _followup,
    _reviewer,
)

from tests.tools.security.test_repair_preflight import operator_handoff

pytestmark = pytest.mark.e2e


def _report(ctx, revision, *, installed, repaired):
    ctx.agent_id = "researcher"
    ctx.trace_id = "source-trace"
    ctx.tool_name = "security.scan_code"
    if installed:
        result = _h_scan_code(
            {
                "target": ".",
                "include_evidence_artifact": True,
                "expected_target_revision": revision,
            },
            ctx,
        )
        assert result["status"] == "completed", result
        scan_ref = result["evidence_refs"][0]
        scan = json.loads(ctx.artifactctl.read_bytes(scan_ref))
        assert bool(scan["findings"]) is not repaired
    else:
        scan = _scan(check="code", revision=revision, finding=not repaired)
        scan.configuration_identity.config_sha256 = hashlib.sha256(
            (ctx.workspace / "rule.yml").read_bytes()
        ).hexdigest()
        scan_ref = _store_scan(ctx, scan)
        scan = scan.model_dump(mode="json")
    findings = (
        []
        if repaired
        else [
            {
                "finding_id": "F-1",
                "basis": "scanner",
                "disposition": "candidate",
                "title": "Fixture grants an ordinary role access",
                "category": "code",
                "severity": "high",
                "confidence": "high",
                "description": "Unconditional authorization.",
                "locations": [{"path": "app.py", "line": 2}],
                "evidence_ref": scan_ref,
                "scanner_finding_ids": [scan["findings"][0]["finding_id"]],
            }
        ]
    )
    ctx.tool_name = "security.publish_report"
    result = _h_publish_report(
        _publish_args(
            revision=revision,
            refs={"code": scan_ref},
            findings=findings,
        ),
        ctx,
    )
    return result["report_ref"]


def run_security_lifecycle(ctx, tmp_path, *, installed=False):
    repo = ctx.workspace
    (repo / "app.py").write_text("def authorize(role):\n    return True\n")
    (repo / "verify.py").write_text(
        "from app import authorize\nassert authorize('admin')\nassert not authorize('guest')\n"
    )
    (repo / "rule.yml").write_text(
        "rules:\n  - id: fixture-unconditional-authorization\n"
        "    languages: [python]\n    message: Fixture unconditional authorization\n"
        "    severity: ERROR\n    pattern: |\n      def authorize($ROLE):\n        return True\n"
    )
    _git("add", ".", cwd=repo)
    _git("commit", "-qm", "test: seed authorization regression", cwd=repo)
    base = _git("rev-parse", "HEAD", cwd=repo)
    source = _report(ctx, base, installed=installed, repaired=False)
    decision = _decision()
    decision["remediation_objective"] = "Authorize only the admin role in app.py."
    decision["verification_criteria"] = ["Guest denied and admin allowed by verify.py."]
    review = _h_review_report(_initial(source, [decision]), _reviewer(ctx))
    commands = (f"{sys.executable} -B verify.py", "git status")

    def verify():
        return run_project_verification_commands(
            commands, workspace=repo, timeout_seconds=20
        )

    before = verify()
    assert before[0].exit_code == 1
    assert _git("status", "--porcelain", cwd=repo) == ""
    handoff = operator_handoff(
        ctx,
        source,
        review["review_ref"],
        base=base,
        before_exit_code=before[0].exit_code,
        paths=["app.py"],
        commands=list(commands),
    )
    store = AutonomyRunStore(root=tmp_path / "autonomy")
    task_db = tmp_path / "tasks.db"
    manager = TaskManager.for_lifecycle_db(db_path=task_db)
    request = build_project_launch_request(
        goal="Repair the accepted fixture finding",
        session_id="repair-session",
        agent_id="parent",
        workspace_boundary=tmp_path,
        repository=repo,
        require_git_repository=True,
        verification_commands=commands,
        verification_timeout_seconds=20,
        task_plan_required=False,
        source_request=handoff,
    )
    run = launch_project(request, store=store, manager=manager)
    calls = []

    class ScriptedModel:
        def delegate(self, **kwargs):
            calls.append("repair")
            child = Path(kwargs["workspace_root"])
            assert child != repo
            assert _git("rev-parse", "HEAD", cwd=child) == base
            (child / "app.py").write_text(
                "def authorize(role):\n    return role == 'admin'\n"
            )
            return A2ADelegateResult(
                ok=True,
                status="success",
                content="Repaired.",
                target_agent_id="implementer",
            )

        def review_readonly(self, **kwargs):
            calls.append("review")
            return A2ADelegateResult(
                ok=True,
                status="success",
                content="Reviewed the bounded patch.",
                target_agent_id=kwargs["reviewer_agent_id"],
                outputs={
                    "review_receipt": {
                        "passed": True,
                        "reviewer_agent_id": kwargs["reviewer_agent_id"],
                        "target_digest": kwargs["target_digest"],
                        "bundle_ref": kwargs["bundle_ref"],
                        "verifier_refs": kwargs["verifier_refs"],
                    }
                },
            )

    adapter = ToolAdapter(
        workspace_root=repo,
        artifactctl=ctx.artifactctl,
        a2a_delegate_api=ScriptedModel(),
        agent_query=lambda: [
            {"agent_id": "implementer"},
            {"agent_id": "code-reviewer"},
        ],
        task_manager=manager,
        agent_id="parent",
    )

    def delegate(mode, **args):
        result = adapter.execute(
            command={
                "tool_name": "task.delegate",
                "command_id": mode,
                "args": {"mode": mode, **args},
                "inputs": {"permission_mode": "bypass"},
                "meta": {"orchestration": {"task_backed_task_id": run.task_id}},
            },
            session_id=run.session_id,
            trace_id=mode,
        )
        assert result["status"] == "success", result
        return result

    def turn(project_request):
        assert all(
            not tool.startswith("security.") for tool in project_request.allowed_tools
        )
        assert source in project_request.prompt and base in project_request.prompt
        repaired = delegate(
            "sync", agent_id="implementer", instruction=handoff, code_bearing=True
        )
        artifact = repaired["outputs"]["child_artifact"]
        record = load_child_worktree_record(ctx.artifactctl, artifact["record_alias"])
        assert record["validation"]["passed"] is True
        assert record["touched_paths"] == ["app.py"]
        assert (repo / "app.py").read_text().endswith("return True\n")
        delegate(
            "review",
            agent_id="code-reviewer",
            instruction="Review only app.py against the accepted criteria.",
            child_artifact=artifact,
            review_criteria=decision["verification_criteria"],
        )
        delegate("accept", child_artifact=artifact)
        record = load_child_worktree_record(ctx.artifactctl, artifact["record_alias"])
        assert record["integration_status"] == "accepted" and record["cleaned_up"]
        assert _git("diff", "--cached", "--name-only", cwd=repo) == "app.py"
        _git("add", "app.py", cwd=repo)
        _git("commit", "-qm", "fix: authorize only the admin fixture role", cwd=repo)
        accepted_ref = ctx.artifactctl.alias_resolve(artifact["record_alias"]).ref
        return ProjectTurnResult(
            summary="Reviewed repair accepted.",
            artifact_refs=(accepted_ref,),
            evidence_refs=(accepted_ref,),
            evidence_kinds=("artifact",),
        )

    finished = ProjectWorker(
        task_manager=manager, autonomy_store=store, turn=turn, verify=verify
    ).run_cycle(run.run_id)
    assert finished.run.status == AutonomyRunStatus.COMPLETED
    patched = _git("rev-parse", "HEAD", cwd=repo)
    assert patched != base and _git("status", "--porcelain", cwd=repo) == ""
    rescan = _report(ctx, patched, installed=installed, repaired=True)
    closure = _h_review_report(_followup(review["review_ref"], rescan), _reviewer(ctx))
    assert closure["review_status"] == "resolved"
    trace = structural_tool_payload(
        {
            "structural_only": True,
            "tool_results": [
                {"tool_name": "security.review_report", "ok": True, "data": review}
            ],
        }
    )
    assert "remediation_objective" not in json.dumps(trace)
    assert decision["remediation_objective"] not in json.dumps(trace)
    manager.close()
    manager = TaskManager.for_lifecycle_db(db_path=task_db)
    store = AutonomyRunStore(root=tmp_path / "autonomy")
    proof = json.loads(Path(finished.run.proof_packet_ref).read_text())
    checkpoint = ProjectCheckpoint.model_validate(
        manager.get_checkpoint(run.task_id, proof["checkpoint_refs"][-1])
    )
    objective = checkpoint.payload["repository_lifecycle"][
        checkpoint.project_run.objective_ledger_ref
    ]
    assert objective["source_request"] == handoff
    accepted_ref = proof["artifact_refs"][0]
    accepted_record = json.loads(ctx.artifactctl.read_bytes(accepted_ref))
    assert accepted_record["integration_status"] == "accepted"
    assert accepted_record["review_receipt"]["passed"] is True
    assert accepted_record["review_receipt"]["reviewer_agent_id"] == "code-reviewer"
    assert accepted_record["validation"]["passed"] is True
    assert (
        accepted_record["review_receipt"]["verifier_refs"]
        == accepted_record["validation"]["verifier_refs"]
    )
    assert (
        source not in proof["artifact_refs"]
        and review["review_ref"] not in proof["artifact_refs"]
    )
    ProjectWorker(
        task_manager=manager,
        autonomy_store=store,
        turn=lambda _: pytest.fail("terminal recovery repeated mutation"),
        verify=lambda: pytest.fail("terminal recovery repeated verification"),
    ).run_cycle(run.run_id)
    manager.close()
    assert calls == ["repair", "review"]
    return {
        "source_report_ref": source,
        "initial_review_ref": review["review_ref"],
        "rescan_report_ref": rescan,
        "follow_up_ref": closure["review_ref"],
        "base_revision": base,
        "patched_revision": patched,
        "proof_packet_ref": finished.run.proof_packet_ref,
        "accepted_child_record_ref": accepted_ref,
    }


def test_security_remediation_retains_review_handoff_after_restart(
    audit_context, tmp_path
):
    ctx, _ = audit_context
    run_security_lifecycle(ctx, tmp_path)
