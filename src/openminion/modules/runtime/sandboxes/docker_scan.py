"""Run an offline scanner and recover only an explicitly owned worker."""

from __future__ import annotations

from typing import Any

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from openminion.modules.runtime.constants import DOCKER_CONTROL_OUTPUT_LIMIT_BYTES
from openminion.modules.runtime.sandboxes.docker import (
    DockerSandboxError,
    DockerSandboxRunner,
)
from openminion.modules.runtime.sandboxes.scan_config import DockerScanConfig


class DockerScanRunner:
    def __init__(self, config: DockerScanConfig) -> None:
        self.config = config
        binary = shutil.which("docker")
        if binary is None:
            raise DockerSandboxError("SANDBOX_UNAVAILABLE", "Docker is unavailable")
        self.binary = str(Path(binary).resolve())
        self.fingerprint = hashlib.sha256(config.model_dump_json().encode()).hexdigest()

    def _command(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        with tempfile.TemporaryDirectory(prefix="openminion-scan-control-") as home:
            try:
                result = subprocess.run(  # noqa: S603 - fixed Docker argv
                    [
                        self.binary,
                        "--config",
                        home,
                        "--host",
                        self.config.daemon_socket,
                        *args,
                    ],
                    capture_output=True,
                    timeout=15,
                    env={"HOME": home, "PATH": "/usr/bin:/bin", "LANG": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise DockerSandboxError(
                    "SANDBOX_UNAVAILABLE", "Docker control command could not complete"
                ) from exc

        if len(result.stdout) + len(result.stderr) > DOCKER_CONTROL_OUTPUT_LIMIT_BYTES:
            raise DockerSandboxError(
                "SANDBOX_UNAVAILABLE", "Docker output limit exceeded"
            )
        if check and result.returncode:
            raise DockerSandboxError(
                "SANDBOX_UNAVAILABLE", "Docker control command failed"
            )
        return result

    def preflight(self) -> str:
        info = json.loads(self._command("info", "--format", "{{json .}}").stdout)
        if info.get("CgroupVersion") != "2":
            raise DockerSandboxError(
                "SANDBOX_UNAVAILABLE", "Scanner requires cgroup v2"
            )
        image = json.loads(
            self._command("image", "inspect", self.config.worker_image).stdout
        )[0]
        if image["Config"].get("Volumes"):
            raise DockerSandboxError(
                "POLICY_DENIED", "Scanner image must not declare volumes"
            )
        return str(image["Id"])

    def run(
        self,
        *,
        input_path: Path,
        session_id: str,
        check: str,
        timeout: float,
        run_owner: str = "",
    ) -> dict[str, Any]:
        image_id = self.preflight()
        name = (
            "openminion-security-scan-"
            + hashlib.sha256(session_id.encode()).hexdigest()[:16]
        )
        stale = self._command("container", "inspect", name, check=False)
        if stale.returncode == 0:
            worker = json.loads(stale.stdout)[0]
            raise DockerSandboxError(
                "SANDBOX_UNAVAILABLE",
                "An interrupted scanner requires exact-ID recovery",
                {"worker_id": worker["Id"], "config_fingerprint": self.fingerprint},
            )
        worker_id = self._create(
            name, image_id, input_path, session_id, check, timeout, run_owner
        )
        failure = None
        try:
            return self._execute(worker_id, image_id, timeout)
        except DockerSandboxError as exc:
            failure = exc
            raise
        finally:
            try:
                self._command("rm", "--force", "--volumes", worker_id)
            except DockerSandboxError as exc:
                exc.details.update(worker_id=worker_id, cleanup_completed=False)
                raise
            if failure is not None:
                failure.details["cleanup_completed"] = True

    def _create(
        self,
        name: str,
        image_id: str,
        input_path: Path,
        session_id: str,
        check: str,
        timeout: float,
        run_owner: str,
    ) -> str:
        config = self.config
        result = self._command(
            "create",
            "--name",
            name,
            "--pull=never",
            "--network=none",
            "--read-only",
            "--user=10001:10001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--no-healthcheck",
            "--log-driver=none",
            f"--pids-limit={config.pids_limit}",
            f"--memory={config.memory_bytes}",
            f"--cpus={config.cpu_limit}",
            "--label",
            f"openminion.security_scan.config={self.fingerprint}",
            "--label",
            f"openminion.security_scan.session={session_id}",
            "--label",
            f"openminion.security_scan.owner={run_owner}",
            "--mount",
            f"type=bind,source={input_path},target=/input.tar,readonly",
            f"--tmpfs=/workspace:rw,noexec,nosuid,nodev,size={config.scratch_bytes},uid=10001,gid=10001,mode=0700",
            "--workdir=/workspace",
            "--entrypoint=python3",
            image_id,
            "-B",
            "/opt/security/worker.py",
            check,
            str(timeout),
            str(config.source_entries),
            str(config.scratch_bytes),
            str(config.max_output_bytes),
        )
        worker_id = result.stdout.decode().strip()
        if len(worker_id) != 64 or any(c not in "0123456789abcdef" for c in worker_id):
            raise DockerSandboxError(
                "SANDBOX_UNAVAILABLE", "Docker returned no worker identity"
            )
        return worker_id

    def _execute(self, worker_id: str, image_id: str, timeout: float) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="openminion-scan-control-") as home:
            process = subprocess.Popen(  # noqa: S603 - fixed Docker argv
                [
                    self.binary,
                    "--config",
                    home,
                    "--host",
                    self.config.daemon_socket,
                    "start",
                    "--attach",
                    worker_id,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": home, "PATH": "/usr/bin:/bin", "LANG": "C"},
            )
            stdout, stderr, _, timed_out, limited = DockerSandboxRunner._read_bounded(
                process, timeout=timeout + 2, output_limit=self.config.max_output_bytes
            )
        state = json.loads(self._command("container", "inspect", worker_id).stdout)[0][
            "State"
        ]
        if timed_out or limited or state.get("OOMKilled") or process.returncode:
            raise DockerSandboxError(
                "EXEC_ERROR",
                "Offline worker did not complete",
                {
                    "worker_id": worker_id,
                    "timed_out": timed_out or state.get("ExitCode") == 124,
                    "output_limited": limited,
                    "memory_limited": bool(state.get("OOMKilled")),
                    "exit_code": process.returncode,
                },
            )
        result: dict[str, Any] = json.loads(stdout)
        result.update(
            worker_id=worker_id, worker_image_digest=image_id, cleanup_completed=True
        )
        return result

    def recover(self, *, worker_id: str, session_id: str) -> dict[str, Any]:
        if len(worker_id) != 64 or any(c not in "0123456789abcdef" for c in worker_id):
            raise ValueError("Recovery requires the complete worker ID")
        worker = json.loads(self._command("container", "inspect", worker_id).stdout)[0]
        labels = worker["Config"].get("Labels") or {}
        if (
            worker["Id"] != worker_id
            or labels.get("openminion.security_scan.config") != self.fingerprint
            or labels.get("openminion.security_scan.session") != session_id
        ):
            raise DockerSandboxError(
                "POLICY_DENIED", "Recovery worker ownership does not match"
            )
        self._command("rm", "--force", "--volumes", worker_id)
        if (
            self._command("container", "inspect", worker_id, check=False).returncode
            == 0
        ):
            raise DockerSandboxError(
                "EXEC_ERROR", "Scanner recovery did not remove the worker"
            )

        return {
            "worker_id": worker_id,
            "run_owner": labels.get("openminion.security_scan.owner", ""),
            "input_path": next(
                (
                    item["Source"]
                    for item in worker.get("Mounts", [])
                    if item["Destination"] == "/input.tar"
                ),
                "",
            ),
            "cleanup_completed": True,
        }
