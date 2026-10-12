import base64
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from openminion.modules.tool.errors import ToolRuntimeError
from openminion.modules.tool import RuntimeContext


def can_read_path(path: Path, ctx: RuntimeContext) -> bool:
    if path.is_symlink():
        return False
    try:
        ctx.policy.ensure_path_allowed(
            str(path), workspace=ctx.workspace, operation="read"
        )
    except ToolRuntimeError:
        return False
    return True


def grep_matches(
    root: Path, *, pattern: str, file_glob: str, max_results: int, ctx: RuntimeContext
) -> list[dict[str, Any]]:
    listing = subprocess.run(
        ["rg", "--files", "--null", "--glob", file_glob, "--", str(root)],
        capture_output=True,
        check=False,
        cwd=str(ctx.workspace),
    )
    if listing.returncode not in (0, 1):
        raise ToolRuntimeError(
            "EXEC_ERROR",
            listing.stderr.decode(errors="replace").strip() or "rg file listing failed",
        )
    paths = [
        os.fsdecode(path)
        for path in listing.stdout.split(b"\0")
        if path and can_read_path(Path(os.fsdecode(path)), ctx)
    ]
    matches: list[dict[str, Any]] = []
    # Bound argv size on platforms with small command-line limits.
    for offset in range(0, len(paths), 128):
        completed = subprocess.run(
            ["rg", "--json", "-e", pattern, "--", *paths[offset : offset + 128]],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(ctx.workspace),
        )
        if completed.returncode not in (0, 1):
            raise ToolRuntimeError(
                "EXEC_ERROR", completed.stderr.strip() or "rg search failed"
            )
        for line in completed.stdout.splitlines():
            event = json.loads(line)
            if event["type"] != "match":
                continue
            data = event["data"]
            file_path = data["path"]
            match_text = data["lines"]
            matches.append(
                {
                    "file": file_path["text"]
                    if "text" in file_path
                    else os.fsdecode(base64.b64decode(file_path["bytes"])),
                    "line": data["line_number"],
                    "text": (
                        match_text["text"]
                        if "text" in match_text
                        else base64.b64decode(match_text["bytes"]).decode(
                            errors="replace"
                        )
                    ).rstrip("\r\n"),
                }
            )
            if len(matches) >= max_results:
                return matches
    return matches
