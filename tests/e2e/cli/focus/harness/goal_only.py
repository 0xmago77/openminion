"""AW-01 fixture and independent acceptance checks; no model instructions added."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

SCENARIO_ID = "aw-01-goal-only"
PROMPT = "Fix the failing tests and finish the change."
LIMITS = {"max_iterations": 4, "max_tool_calls": 24, "max_wall_clock_ms": 900_000}
ALLOWED_APPROVALS = (
    "file.list_dir",
    "file.find",
    "file.read",
    "file.read_range",
    "file.search",
    "file.write",
    "file.edit",
    "code.grep",
    "code.symbol_find",
    "code.repo_map",
    "code.repo_index",
    "code.patch",
    "exec.run",
    "project.start",
)
SOURCE_PATHS = {"stats.py", "mean.py"}
READ_ONLY_COMMANDS = (
    "pwd",
    "ls",
    "ls -la",
    "git status",
    "git status --short",
    "git status --porcelain",
    "git diff",
    "git diff HEAD",
    "git diff --stat",
    "git diff --check",
    "git ls-files",
    "git log -1",
    "git log --oneline",
    "python --version",
    "python3 --version",
    "python3.11 --version",
)
FIXTURE = {
    "AGENTS.md": "Keep changes minimal. Change source files only; preserve tests.\n",
    ".gitignore": ".pytest_cache/\n__pycache__/\n",
    "stats.py": "def total(values):\n    raise NotImplementedError\n",
    "mean.py": "def mean(values):\n    raise NotImplementedError\n",
    "test_stats.py": (
        "import pytest\nfrom stats import total\nfrom mean import mean\n\n"
        "@pytest.mark.parametrize('values, expected', [([2, 4, 6], 12), "
        "([-2, -4, -6], -12), ([], 0)])\n"
        "def test_total(values, expected):\n    assert total(values) == expected\n\n"
        "@pytest.mark.parametrize('values, expected', [([2, 4, 6], 4), "
        "([-2, -4, -6], -4)])\n"
        "def test_mean(values, expected):\n    assert mean(values) == expected\n\n"
        "def test_mean_empty():\n    with pytest.raises(ValueError):\n        mean([])\n"
    ),
}
ORACLE = """import sys
sys.path.insert(0, sys.argv[1])
from stats import total
from mean import mean
for values, expected in [([2, 4, 6], 12), ([-2, -4, -6], -12), ([], 0),
                         ([1.5, -0.5], 1), ([17], 17)]:
    assert total(values) == expected, (values, expected)
for values, expected in [([2, 4, 6], 4), ([-2, -4, -6], -4),
                         ([1.5, -0.5], 0.5), ([17], 17)]:
    assert mean(values) == expected, (values, expected)
try:
    mean([])
except ValueError:
    pass
else:
    raise AssertionError("empty mean must raise ValueError")
print("aw-01 independent oracle: 10 passed")
"""


def digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def git(workspace: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(workspace), *args], text=True
    ).strip()


def seed_fixture(workspace: Path) -> dict[str, object]:
    workspace.mkdir(parents=True)
    for name, text in FIXTURE.items():
        (workspace / name).write_text(text, encoding="utf-8")
    git(workspace, "init", "-q", "-b", "main")
    git(workspace, "config", "user.name", "AW-01 fixture")
    git(workspace, "config", "user.email", "aw01@example.invalid")
    git(workspace, "add", ".")
    git(workspace, "commit", "-qm", "Seed failing fixture")
    return {
        "prompt_sha256": digest(PROMPT),
        "fixture_sha256": digest(json.dumps(FIXTURE, sort_keys=True)),
        "fixture_file_sha256": {name: digest(text) for name, text in FIXTURE.items()},
        "oracle_sha256": digest(ORACLE),
        "seed_revision": git(workspace, "rev-parse", "HEAD"),
        "history_sha256": digest(git(workspace, "reflog", "--all", "--format=%H %gs")),
        "allowed_changed_paths": sorted(SOURCE_PATHS),
    }


def assert_fixture_integrity(workspace: Path, frozen: dict[str, object]) -> str:
    assert git(workspace, "rev-parse", "HEAD") == frozen["seed_revision"], (
        "fixture Git history changed"
    )
    assert git(workspace, "rev-list", "--all") == frozen["seed_revision"], (
        "fixture gained unrelated Git history"
    )
    assert (
        digest(git(workspace, "reflog", "--all", "--format=%H %gs"))
        == frozen["history_sha256"]
    ), "fixture Git history was modified and restored"
    assert not git(workspace, "remote"), "fixture gained a Git remote"
    files = {
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if path.is_file() or path.is_symlink()
        if not {".git", ".pytest_cache", "__pycache__"}.intersection(
            path.relative_to(workspace).parts
        )
    }
    assert files == FIXTURE.keys(), "unexpected or missing fixture files"
    for name, original in FIXTURE.items():
        path = workspace / name
        assert not path.is_symlink(), f"fixture symlink: {name}"
        if name not in SOURCE_PATHS:
            assert path.read_bytes() == original.encode(), (
                f"protected file changed: {name}"
            )
    changed = set(git(workspace, "diff", "--name-only", "HEAD", "--").splitlines())
    assert changed == SOURCE_PATHS, f"expected both source changes, got {changed}"
    diff = subprocess.check_output(
        ["git", "-C", str(workspace), "diff", "--binary", "HEAD", "--"], text=True
    )
    assert diff, "empty change"
    return diff


def verify_fixture(
    workspace: Path, frozen: dict[str, object], python_bin: Path
) -> dict[str, object]:
    before = assert_fixture_integrity(workspace, frozen)
    result = subprocess.run(
        [str(python_bin), "-I", "-B", "-c", ORACLE, str(workspace)],
        cwd=workspace.parent,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "aw-01 independent oracle: 10 passed", result.stdout
    assert assert_fixture_integrity(workspace, frozen) == before, (
        "verification mutated the fixture"
    )
    return {"exit_code": result.returncode, "stdout": result.stdout, "git_diff": before}


def pytest_command(command: str, workspace: Path) -> bool:
    """Recognize direct whole-fixture pytest, never shell output posing as a check."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return False
    if not argv:
        return False
    if "/" in argv[0] and Path(argv[0]).resolve() != Path(sys.executable).resolve():
        return False
    executable = Path(argv[0]).name
    if executable == "pytest":
        args = argv[1:]
    elif re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable) and argv[1:3] == [
        "-m",
        "pytest",
    ]:
        args = argv[3:]
    else:
        return False
    return all(
        arg
        in {
            "-q",
            "-v",
            "-vv",
            "-x",
            "--disable-warnings",
            "--tb=short",
            ".",
            "test_stats.py",
            str(workspace),
            str(workspace / "test_stats.py"),
        }
        for arg in args
    )


def model_verifiers(
    events: list[dict],
    *,
    session_ids: set[str],
    gateway_run_ids: set[str],
    agent_id: str,
    workspace: Path,
) -> list[dict]:
    scoped = [
        event
        for event in events
        if event["session_id"] in session_ids and event["agent_id"] == agent_id
    ]
    invocation_ids = {
        event["invocation_id"]
        for event in scoped
        if event["event_type"] == "agent.invocation.started"
        and event["data"].get("run_id") in gateway_run_ids
    }
    scoped = [
        event
        for event in scoped
        if event.get("invocation_id") in invocation_ids and event.get("execution_id")
    ]
    identities = {
        (
            event["session_id"],
            event["turn_id"],
            event["invocation_id"],
            event["execution_id"],
        )
        for event in scoped
        if event["event_type"] == "agent.turn.started"
    }
    requests = {
        (
            event["session_id"],
            event["turn_id"],
            event["invocation_id"],
            event["execution_id"],
            event["data"].get("call_id"),
        ): event
        for event in scoped
        if event["event_type"] == "tool.call.requested"
        and (
            event["session_id"],
            event["turn_id"],
            event["invocation_id"],
            event["execution_id"],
        )
        in identities
    }
    completed_turns = {
        (
            event["session_id"],
            event["turn_id"],
            event["invocation_id"],
            event["execution_id"],
        )
        for event in scoped
        if event["event_type"] == "agent.turn.completed"
    }
    verified = []
    for event in scoped:
        if event["event_type"] != "tool.call.completed":
            continue
        data = event["data"]
        key = (
            event["session_id"],
            event["turn_id"],
            event["invocation_id"],
            event["execution_id"],
            data.get("call_id"),
        )
        request = requests.get(key)
        if request is None or request["data"].get("canonical_name") != "exec.run":
            continue
        args = request["data"]["sanitized_normalized_arguments"]
        command = str(args.get("command", ""))
        if not pytest_command(command, workspace):
            continue
        cwd = (workspace / str(args.get("workdir") or ".")).resolve()
        output = data.get("output", {}).get("outputs", {})
        if (
            cwd == workspace.resolve()
            and not args.get("env")
            and data.get("status") == "success"
            and output.get("status") == "ok"
            and output.get("exit_code") == 0
            and re.search(r"\b6 passed\b", str(output.get("stdout", "")))
            and key[:-1] in completed_turns
            and not any(
                later["event_type"] == "tool.call.requested"
                and later["data"].get("canonical_name")
                in {"file.write", "file.edit", "code.patch"}
                for later in scoped[scoped.index(event) + 1 :]
            )
        ):
            verified.append({"request": request, "result": event})
    assert verified, "missing current successful model-invoked whole-fixture verifier"
    return verified


def assert_local_request(name: str, args: dict, workspace: Path) -> None:
    """Bounded test authority, not a replacement shell policy or sandbox."""
    if name == "plan":
        return
    if name == "tool.request":
        assert args.get("name") in ALLOWED_APPROVALS, "out-of-scope tool request"
        return
    assert name in ALLOWED_APPROVALS, f"out-of-scope tool: {name}"
    assert name != "project.start", "durable_exec_scope_unbound"
    if name == "exec.run":
        assert not args.get("background"), "background exec outside campaign ownership"
        assert not args.get("env"), "exec environment override"
        assert not args.get("node") and args.get("host") != "node", "remote exec host"
        assert (workspace / str(args.get("workdir") or ".")).resolve() == workspace, (
            "exec outside fixture"
        )
        command = str(args.get("command", ""))
        assert command in READ_ONLY_COMMANDS or pytest_command(command, workspace), (
            f"exec command outside frozen direct-command authority: {command}"
        )
        return
    path = args.get("path")
    if name in {"file.write", "file.edit", "code.patch"}:
        assert path and (workspace / str(path)).resolve() in {
            workspace / item for item in SOURCE_PATHS
        }, "attempted mutation of a protected or external path"
    elif path:
        resolved = (workspace / str(path)).resolve()
        assert resolved == workspace or workspace in resolved.parents, (
            "read outside fixture"
        )


def assert_terminal(terminal: dict, *, session_ids: set[str]) -> None:
    assert terminal.get("session_id") in session_ids, "foreign terminal session"
    assert terminal.get("answer", "").strip(), "missing terminal answer"
    assert not terminal.get("run_id"), "durable_exec_scope_unbound"
    assert terminal.get("status") in {"done", "completed"}, "incomplete terminal state"
    assert terminal.get("finalization_status") == "final_answer", (
        "missing final answer contract"
    )
