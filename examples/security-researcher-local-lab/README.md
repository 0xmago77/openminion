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

## Prepare the synthetic target

Use an already-local digest-pinned image containing `python3` and its standard
library, supporting numeric UID/GID `10001:10001`, and declaring no volumes.
Set `lab_socket` to the same local Unix socket as `runtime.security_lab.daemon_socket`.
Replace the image placeholder before running this example; it never pulls an
image. Keep the separately configured worker image pinned and already local too.

```bash
lab_socket='unix:///absolute/path/to/docker.sock'
lab_target_image='target-repository@sha256:APPROVED_DIGEST'
lab_target_id=$(docker --host "$lab_socket" run --detach \
  --name openminion-security-target --pull=never --network=none \
  --read-only --user=10001:10001 --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=32 --cpus=0.5 \
  --memory=67108864 --restart=no --no-healthcheck \
  --entrypoint=python3 "$lab_target_image" -B -u -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"synthetic authorization bypass: guest received fixture data"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = HTTPServer(("0.0.0.0", 8080), Handler)
print("fixture ready", flush=True)
server.serve_forever()
')
docker --host "$lab_socket" logs "$lab_target_id"
```

Confirm `fixture ready` before activation. This deliberately defective HTTP
fixture contains synthetic data only. No host ports or directories are mounted;
`http://127.0.0.1:8080/defect` is reachable by the approved worker sharing the
target network namespace, not by a host browser. An existing target with this
name must be inspected separately; do not replace it blindly.

## Activate the profile

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
the profile when the bounded test is complete. Then remove only the target ID
returned by your setup command:

```bash
docker --host "$lab_socket" rm --force --volumes "$lab_target_id"
```
