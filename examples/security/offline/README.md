# Offline security worker

This example adds isolated scans of approved local archives. It does not install
or download assets during assessment. Prepare assets on an operator-controlled
machine and use an immutable image reference after building.

## Prepare assets

Create a private build directory outside the source tree. Copy this example's
`rules.yml` plus `src/openminion/tools/security/worker.py` and `web_checks.py` into
it. Prepare a current Trivy database in `trivy-cache/db/` using an approved Trivy
installation (`trivy image --download-db-only --cache-dir trivy-cache`). Create
`manifest.json` containing `{"database_max_age_seconds":172800}`. The runtime
hashes the actual database bytes; it never trusts a caller-supplied database hash.

Build using reviewed, immutable `TRIVY_IMAGE` and `PYTHON_IMAGE` base references:

```bash
docker build --build-arg TRIVY_IMAGE="$TRIVY_IMAGE" \
  --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" \
  -f examples/security/offline/Dockerfile --iidfile /private/build/worker.id \
  /private/build
```

The example pins Semgrep 1.174.0. Its Python/JavaScript rules are deliberately
small fixture rules; operators own rules suitable for their audit. Updating
rules, databases or the worker requires rebuilding and approving a new immutable
worker. A registry `repo@sha256:...` or locally built `sha256:...` image ID is
accepted. The image must already be present and declare no Docker volumes.

Set `OPENMINION_SECURITY_SCAN_CONFIG` to an operator-owned JSON file:

```json
{
  "docker": {
    "daemon_socket": "unix:///absolute/path/to/docker.sock",
    "worker_image": "sha256:<full-local-image-id>"
  },
  "targets": {
    "source-fixture": {"root": "/approved/archives", "kind": "source_snapshot"},
    "image-fixture": {"root": "/approved/archives", "kind": "container_archive"}
  }
}
```

Prepare a plain tar of source files, or `docker save` one already-owned local
image. Supply the archive SHA256 with every call. Symlinks, devices, traversal,
multiple images and oversized archives are rejected. Do not execute the assessed
archive to prepare it. The 100 MiB default intentionally excludes large images.

Install/admit the `security-researcher-offline` skill and identity through the
same commands used by the [readonly researcher](../../security-researcher-readonly/README.md),
substituting that profile name. Start Focus with `--no-context`, enable readonly
mode, and activate `security_offline` and `security_reporting`. Supply exact
target IDs, paths and hashes. Offline AWS input must be ingested into canonical
artifact storage under the actual executing session; the schema is defined in
`openminion.tools.security.aws_snapshot.AwsSnapshot`.

## Interrupted worker recovery

A worker has an internal deadline even if its supervising process disappears.
After a crash, a subsequent scan refuses the stale session worker. An operator
must inspect its full ID and invoke
`openminion.tools.security.offline.recover_archive_scan` with the same Docker
configuration, artifact store and exact creating session. Recovery checks
configuration/session labels, removes only that worker, releases its active
archive reference and deletes its private staged input. This is not an agent
capability. Never delete workers by broad name prefix.

## Recurring trusted source

Use the original readonly researcher identity with `security_readonly` active.
The root must be a clean local Git checkout. Keep the same rule file used in the
worker available at `OPENMINION_SECURITY_SEMGREP_CONFIG` for source-report
validation. This mode uses Git only on the explicitly trusted source root.

The schedule configuration is a JSON object keyed by exact agent ID. Each value
has this shape (replace all placeholders):

```json
{
  "security-researcher-readonly": {
    "schema_version": "security-source-schedule/v1",
    "agent_id": "security-researcher-readonly",
    "root": "/approved/repository",
    "checks": ["code"],
    "allowed_tools": ["security.scan_code", "security.publish_report"],
    "config_fingerprint": "<sha256 of scan-config bytes followed by local rules bytes>",
    "expires_at": "2026-10-29T00:00:00Z",
    "max_runs": 2,
    "timeout_seconds": 120
  }
}
```

Set `OPENMINION_SECURITY_SCHEDULE_CONFIG` to this file. An optional `baseline_ref`
can name a canonical source report by the same agent. `task.schedule` stores the
trusted admission and pins the baseline's scan dependencies. The model cannot
supply a broader admission. Changing the file invalidates existing admissions;
create a new explicitly approved schedule instead of silently migrating it.
Use existing task pause/cancel controls to stop future ticks. History remains
pinned until explicitly disposed through the artifact owner's collection refs.

## Live fixtures

`test_offline_scan.py`, `test_web_checks.py` and `test_security_schedule.py` under
`tests/e2e/security_lab/` use explicit Docker opt-ins. The schedule fixture runs
real workers and persistent cron records with a scripted model dispatcher;
MiniMax tool/report and repair proof are separate Focus harnesses.
