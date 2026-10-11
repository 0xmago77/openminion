# CLI

`cli/` is the argparse command-line entry surface for OpenMinion.

Entry:
- `main.py` — `python -m openminion` dispatches here

Top-level settings:
- `config.py`
- `constants.py`

Subpackages:
- `commands/` — subcommand handlers bound by the parser
- `interactive/` — shared interactive runtime and project-context ownership
- `interactive/terminal/` — canonical terminal shell and renderer
- `status/` — status-line rendering helpers

Grouped helpers:
- `bootstrap/` — CLI-specific config resolution and path setup
- `parser/` — argparse construction and CLI contracts
- `identity/` — identity resolution at the CLI boundary
- `transport/` — daemon and in-process runtime transport helpers
- `presentation/` — ANSI styling and output formatting helpers
- `presentation/animation/` — activity frame/timing provider validation,
  built-in fallback, optional provider discovery, and interactive animation
  resolution
Compatibility note:
- `openminion.cli.<module>` compatibility imports remain supported through
  `openminion.cli.__init__` aliases while implementation helpers stay in their
  owning subpackages.

Delegation scope:
- `agent delegate`, `delegate-list`, `delegate-status`, `delegate-result`,
  `delegate-resume`, and `delegate-cancel` accept `--parent-agent-id` and
  `--session-id` after the operation. They pass that exact scope to the existing
  delegation runtime and ownership checks.
- `agent --session-id <id> delegate-list` remains valid. Omitting explicit scope
  retains the configured default agent and existing unscoped CLI behavior.
- Accepting scope does not add job resume support or an inspection command.
