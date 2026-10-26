# Local Security Lab Example

This opt-in profile runs one approved direct command against an operator-owned
synthetic Docker target. It does not authorize remote, production,
authenticated, destructive, or persistent testing.

Keep your normal provider configuration and default agent. Copy the `identity`
block, `runtime.security_lab` block, and `security-researcher-local-lab` agent
entry from [profile.json](profile.json) into that configuration. Replace the
example echo provider with your configured provider. Keep
`structural_tool_results=true` so saved tool-result metadata contains structural
facts and canonical references rather than command arguments or output bodies.
Canonical artifacts retain the execution evidence.

Before use, configure your local Unix Docker socket and replace the worker image
placeholder with an already-local image reference pinned by digest. Prepare a disposable target named
`openminion-security-target` with `network_mode=none`, a read-only root,
non-root user, dropped capabilities, no mounts or ports, and bounded CPU,
memory, and PIDs.

Stage the matching skill:

```bash
openminion skill ingest \
  --file examples/skills/security-researcher-local-lab/SKILL.md \
  --name security-researcher-local-lab \
  --scope agent \
  --agent-id security-researcher-local-lab \
  --trust trusted_local
```

Record the returned `version_hash` and admit that exact version. Use `none`
only for first admission; otherwise supply the current active version hash.

```bash
openminion skill admit \
  --skill-id security-researcher-local-lab \
  --version-hash <version-hash> \
  --expected-active-version-hash none \
  --target-status verified \
  --reason "Approved synthetic local lab procedure"
```

Load the identity and start Focus without project context:

```bash
openminion identity upsert examples/identity/security-researcher-local-lab.yaml
openminion --profile security-researcher-local-lab --no-context
```

An identified human must approve a finite activation:

```text
/tools activate security_lab approved=yes ttl=300 approved_by=<operator> reason="approved synthetic target"
```

Each `exec.run` still requires normal confirmation and must use
`host=sandbox`, `security=deny`, foreground mode, no environment or workdir,
and `include_evidence_artifact=true`. Publish only candidate or rejected
findings whose evidence belongs to the same live activation.

If a host crash leaves a worker, inspect its
`openminion.security_lab.session` label and remove that exact container with
`docker rm --force <container-id>` before approving another run. Deactivate
the profile when the bounded test is complete.
