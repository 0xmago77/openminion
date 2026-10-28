"""Offline scanner entry point copied into the pinned worker image."""

from __future__ import annotations

from typing import Any

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import signal
import selectors
import subprocess
import sys
import tarfile
from datetime import datetime, timezone


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unpack_snapshot(archive: Path, destination: Path, entries: int, limit: int) -> None:
    total = 0
    with tarfile.open(archive, "r:") as source:
        for count, member in enumerate(source, 1):
            path = PurePosixPath(member.name)
            total += member.size
            if count > entries or total > limit:
                raise ValueError("Source archive exceeds its entry or expansion limit")
            if (
                path.is_absolute()
                or ".." in path.parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("Source archive contains an unsafe entry")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source.extractfile(member)
                assert stream is not None
                with stream, target.open("xb") as output:
                    for chunk in iter(lambda: stream.read(65_536), b""):
                        output.write(chunk)


def image_identity(archive: Path, entries: int) -> str:
    identity = None
    with tarfile.open(archive, "r:") as source:
        for count, member in enumerate(source, 1):
            if count > entries:
                raise ValueError("Image archive exceeds its entry limit")
            if member.name != "manifest.json":
                continue
            if identity is not None or not member.isfile() or member.size > 1_048_576:
                raise ValueError("Invalid Docker-save manifest")
            stream = source.extractfile(member)
            assert stream is not None
            with stream:
                manifest = json.load(stream)
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise ValueError("Expected exactly one Docker-save image")
            identity = str(manifest[0]["Config"])
    if not identity:
        raise ValueError("Docker-save manifest is missing")
    return identity


def scan(check: str, entries: int, scratch: int, output_limit: int) -> dict[str, Any]:
    archive = Path("/input.tar")
    target = Path("/workspace/source")
    target.mkdir()
    image_config = ""
    if check == "image":
        image_config = image_identity(archive, entries)
    else:
        unpack_snapshot(archive, target, entries, scratch)
    rules = Path("/opt/security/rules.yml")
    database_digest = ""
    if check == "code":
        binary = "semgrep"
        argv = [
            binary,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            "--error",
            "--config",
            str(rules),
            ".",
        ]
        mode = "code"
    else:
        binary = "trivy"
        mode = {
            "dependencies": "vuln",
            "image": "vuln",
            "iac": "misconfig",
            "secrets": "secret",
        }[check]
        database = Path("/opt/security/cache/db/trivy.db")
        database_digest = file_digest(database)
        metadata = json.loads(database.with_name("metadata.json").read_text())
        policy = json.loads(Path("/opt/security/manifest.json").read_text())
        updated = datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
        if (datetime.now(timezone.utc) - updated).total_seconds() > policy[
            "max_database_age_hours"
        ] * 3600:
            raise ValueError("Scanner database exceeds the prepared freshness policy")
        argv = [
            binary,
            "image" if check == "image" else "fs",
            "--format",
            "json",
            "--quiet",
            "--no-progress",
            "--exit-code",
            "1",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--cache-backend",
            "memory",
            "--cache-dir",
            "/opt/security/cache",
            "--scanners",
            mode,
        ]
        argv += ["--input", str(archive)] if check == "image" else ["."]
    version = subprocess.run([binary, "--version"], capture_output=True, check=True)  # noqa: S603
    return_code, stdout, stderr = run_bounded(argv, target, output_limit)
    return {
        "scanner": binary,
        "scanner_version": version.stdout.decode().splitlines()[0],
        "scan_mode": mode,
        "config_sha256": file_digest(rules) if check == "code" else "",
        "database_sha256": database_digest,
        "fixed_flags": argv[1:-2] if check == "image" else argv[1:-1],
        "return_code": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "image_config": image_config,
    }


def run_bounded(argv: list[str], cwd: Path, limit: int) -> tuple[int, str, str]:
    with subprocess.Popen(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:  # noqa: S603
        assert process.stdout is not None and process.stderr is not None
        output = {
            process.stdout.fileno(): bytearray(),
            process.stderr.fileno(): bytearray(),
        }
        total = 0
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                for key, _ in selector.select():
                    chunk = os.read(key.fd, min(65_536, limit - total + 1))
                    total += len(chunk)
                    if total > limit:
                        process.kill()
                        raise ValueError("Scanner output exceeded its limit")
                    if chunk:
                        output[key.fd].extend(chunk)
                    else:
                        selector.unregister(key.fileobj)
        return (
            process.wait(),
            output[process.stdout.fileno()].decode(),
            output[process.stderr.fileno()].decode(),
        )


def main() -> int:
    check, timeout, entries, scratch, output_limit = sys.argv[1:]
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(math.ceil(float(timeout)))
    os.environ.update(
        HOME="/workspace",
        TMPDIR="/workspace",
        SEMGREP_SEND_METRICS="off",
        SEMGREP_ENABLE_VERSION_CHECK="0",
    )
    try:
        result = scan(check, int(entries), int(scratch), int(output_limit))
    except (
        ValueError,
        KeyError,
        OSError,
        tarfile.TarError,
        subprocess.CalledProcessError,
    ) as exc:
        print(json.dumps({"error": type(exc).__name__}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
