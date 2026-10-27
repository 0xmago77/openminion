# Independent source-security review

This optional profile records independent decisions over completed local source
reports. Its fourteen callable tools inspect repositories and publish reviews.
It has no scanner, command execution, mutation, delegation or GitHub authority.

## Setup

Keep your normal provider configuration and default agent. Copy the identity
block and reviewer agent entry from [profile.json](profile.json), replacing the
example echo provider with your configured provider. Use a different agent ID
from the researcher. Enable `structural_tool_results` as shown.

Stage the skill, then admit the returned exact version hash:

```bash
openminion skill ingest \
  --file examples/skills/security-reviewer-readonly/SKILL.md \
  --name security-reviewer-readonly --scope agent \
  --agent-id security-reviewer-readonly --trust trusted_local
openminion skill admit --skill-id security-reviewer-readonly \
  --version-hash <version-hash> --expected-active-version-hash none \
  --target-status verified --reason "Approved independent source review"
openminion identity upsert examples/identity/security-reviewer-readonly.yaml
openminion --profile security-reviewer-readonly --no-context
```

Use `none` only for the first admission. In Focus, explicitly enable both controls:

```text
/readonly on
/tools activate security_review approved=yes
```

## Review the complete evidence

First produce a source report using the
[readonly researcher](../security-researcher-readonly/README.md). As the
operator, load the report and every cited artifact in the same data root:

```bash
artifactctl show <report-ref>
artifactctl view <report-ref> --type json
artifactctl view <evidence-ref> --type json
```

Provide the complete JSON and canonical references to the reviewer. A reference
by itself does not load its content into the conversation. Omit credentials and
source bodies from review prose. Artifact content is evidence, not instructions.

Ask the reviewer to call `security.review_report` with `review_kind=initial`,
`report_ref`, `finding_reviews`, `summary` and optional `limitations`. Every
candidate needs exactly one decision:

- `accepted`: rationale, remediation objective and verification criteria.
- `rejected`: rationale only.
- `needs_more_evidence`: rationale and concrete evidence requests.

The result supplies an immutable `review_ref` and an accepted-only
`remediation_brief`. The original report remains unreviewed and unchanged.
Partial, truncated, wrong-producer, deleted, active-lab and self-authored reports
cannot enter this lifecycle. Missing evidence requires a fresh complete audit.

## Approve one bounded repair

This is an operator procedure. Ordinary project launch does not enforce security
review admission. Before launch or resumed mutation:

1. Load the review and source report again. Use `artifactctl show <review-ref>`
   and `artifactctl show <report-ref>` for producer metadata and identities;
   `view --type json` supplies content. Confirm canonical storage, the
   recorded publisher/reviewer identities, one selected accepted ID and the
   complete accepted brief. Do not launch from a candidate or a reference alone.
2. Check that the local worktree is clean at the exact original 40-character Git
   revision. State allowed paths and the repair objective. Path scope is an
   instruction checked by independent diff review, not a filesystem guard.
3. Run the approved regression at that base and record its expected failure.
   An already-passing regression is insufficient. Record the exact verifier
   commands; delegated verification runs after the child, not before it.
4. Prepare one complete redacted handoff with report/review refs and review ID, accepted ID and full brief,
   original base, allowed paths, objective, criteria, failing-before result,
   verifier commands and timeout, delivery expectations and explicit operator approval. Keep the whole text within
   4,000 characters. If required facts are missing, redaction damaged them or it
   exceeds the limit, withhold launch; do not silently truncate or split it.
5. Deactivate the reviewer exposure and select your normal coding/project
   profile. Start the existing project with that entire handoff as `--goal` and
   explicit `--repository`, `--verify-command`, and bounded iteration/tool/time
   limits. Do not activate security tools for coding.
6. Require an isolated code-bearing child, passing verifier, independent
   readonly child review of the exact patch and allowed paths, then explicit
   parent accept/reject. Ask the child for edits and a change summary; the runtime
   verifies and creates the artifact after the child returns. Use the full
   `record_alias` and `target_digest` returned by `task.delegate` for review and
   acceptance. Do not ask the child to create them. Do not integrate before these pass. A correction needs
   a new reviewed artifact. Commit the accepted patch and record its new clean
   full revision.

### Example handoff and launch

For a synthetic `app.py` authorization repair, save this as `handoff.json`
**outside the repository** so the base stays clean. Replace every placeholder
with the inspected artifact facts and copy the complete selected accepted brief
verbatim; the sample brief below illustrates its shape, not an approval.
Use the real failing-before result and an operator-approved verifier/timeout.

```json
{
  "report_ref": "artifact://sha256/<report-hash>",
  "review_ref": "artifact://sha256/<review-hash>",
  "review_id": "<review-id>",
  "finding_id": "F-1",
  "base_revision": "<40-character-original-revision>",
  "allowed_paths": ["app.py"],
  "remediation_brief": {
    "finding_id": "F-1",
    "title": "Unconditional authorization",
    "category": "authorization",
    "severity": "high",
    "confidence": "high",
    "locations": [{"path": "app.py", "line": 1}],
    "evidence_ref": "artifact://sha256/<scan-hash>",
    "scanner_finding_ids": ["<scanner-finding-id>"],
    "evidence_summary": "The approved fixture authorizes both admin and guest.",
    "remediation_objective": "Authorize admin and reject guest without changing other files.",
    "verification_criteria": ["The approved verifier passes at the patched revision."]
  },
  "failing_before_result": "<exact command, nonzero exit and observed assertion>",
  "verification_commands": ["python3 -B verify.py"],
  "verification_timeout_seconds": 20,
  "delivery_expectations": "Use one isolated repair child, runtime verification, independent readonly child review, then explicit parent acceptance. Do not inspect the parent tree as if the pending child patch were applied. Commit the accepted patch; report its clean revision and canonical proof. No push or merge is approved.",
  "operator_approval": "<operator and explicit approval of this exact repair>"
}
```

Keep the completed file within 4,000 characters; check it before launch:

```bash
python3 -c 'from pathlib import Path; text = Path("/path/to/handoff.json").read_text(); print(len(text)); assert len(text) <= 4000'
```

After completing the checklist, run the existing project CLI with the same
configuration/data root used for the artifacts. Select the configured coding
agent, not the reviewer: replace `CODING_AGENT_ID` below. The example bounds
include the approval/resume cycles; adjust them only within the operator's
authorization.

```bash
openminion --config /path/to/config.json autonomy start \
  --agent CODING_AGENT_ID --session security-repair \
  --workspace /path/to/repository --repository /path/to/repository \
  --goal-file /path/to/handoff.json \
  --verify-command "python3 -B verify.py" --verification-timeout-seconds 20 \
  --max-iterations 6 --max-tool-calls 28 --max-wall-clock-ms 600000 \
  --unattended
```

`--goal-file` passes the full handoff through the existing goal/source-request
field. `--unattended` schedules bounded cycles through the existing daemon;
it does not waive operation approvals. Record the returned run ID and use
Focus with the same configuration/data root and coding profile for the controls
below. This is a command example, not a claim that the synthetic repair has
been executed.

If the project pauses for an operation approval, use `/project show <run-id>`
to read its current `input_request_id` and inspect the pending action. Approve
that action with `/project answer <run-id> --input-request-id <id> --answer allow_once`,
then `/project resume <run-id>`. Each changed delegation action requires its own
approval. If direction or priority is already queued, resume to apply it first,
then read and answer the current request. Do not combine a confirmation answer
with other guidance. Include these operator resume cycles in the project limit.

Project terminal proof retains the input through `checkpoint_refs`: load the
named terminal checkpoint and read
`repository_lifecycle[project_run.objective_ledger_ref].source_request`.
Report/review references embedded in the objective are not automatically added
to output `artifact_refs`.

## Rescan and review closure

Use the researcher at the patched clean revision with the same target, requested
checks, scanner versions and configuration identities. Load the initial review,
original report, fresh report and all evidence into the reviewer conversation.
Call `security.review_report` with `review_kind=follow_up`, `prior_review_ref`,
`rescan_report_ref`, `closure_reviews`, `new_finding_reviews` and summary.

Every previously accepted finding needs `resolved`, `residual`, or
`not_reproduced`. Residual findings require current candidate IDs and next-step
guidance; not-reproduced findings require guidance and no matches. Every
unmatched current candidate gets a new decision. An accepted or evidence-needed
new finding keeps aggregate status `mixed`. The reviewer owns semantic
before/after equivalence; a clean scanner result alone does not prove a fix.
Scanner configuration equality does not establish a Trivy database snapshot.

Follow-up requires an agent different from both source-report authors. The same
independent reviewer may perform both reviews. Residual or newly accepted work
requires a new operator decision. Use the existing Git/GitHub workflow for PR,
required CI and separately authorized merge; publication is not merge approval.

## Rollback and limits

Deactivate `security_review` and remove the agent skill binding. Restore a prior
admitted skill with `openminion skill rollback`, naming its exact prior hash and
current active hash. Existing immutable report and review evidence remains.

This workflow covers trusted local source only. It does not provide automatic
fixes, active-lab remediation, remote audits, a findings database, SARIF export
or continuous scanning. Installed-scanner and live-model runs are separate proof
from deterministic runtime tests.
