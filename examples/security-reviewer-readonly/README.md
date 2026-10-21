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
openminion artifactctl show <report-ref>
openminion artifactctl view <report-ref> --type json
openminion artifactctl view <evidence-ref> --type json
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
   parent accept/reject. Do not integrate before these pass. A correction needs
   a new reviewed artifact. Commit the accepted patch and record its new clean
   full revision.

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
