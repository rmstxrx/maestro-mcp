# ADR-0007 Phase 2 Mux Layer

## Summary

Implemented `maestro/mux.py` as a tmux-backed execution layer for bash hosts, routed `fleet.exec()` and bash `fleet.script()` through it, wired the new module in `server.py`, added `tmux` to the container image, and verified the full test suite.

## Files Changed

- `maestro/mux.py` — Added the late-bound tmux multiplexer module with `configure_mux()`, `ensure_session()`, `mux_run()`, and the ephemeral wrapper builder.
- `maestro/tools/fleet.py` — Switched `exec` and non-PowerShell `script` execution from direct transport/local helpers to `mux_run()` while preserving the existing PowerShell raw-SSH path and tool return formats.
- `server.py` — Wired `configure_mux()` with `_resolve_host`, `_ssh_run`, `_local_run`, and `_format_result` during startup.
- `Dockerfile` — Added `tmux` to the runtime package set alongside `openssh-client`.
- `tests/test_mux.py` — Added unit coverage for wrapper generation, heredoc verbatim handling, cwd flag handling, and sudo vs non-sudo execution.

## Decisions And Surprises

- Kept PowerShell out of the mux path entirely and made `mux_run()` reject it, so the existing raw-SSH behavior remains explicit in `fleet.py`.
- For bash scripts, preserved the current `set -euo pipefail` plus optional `cd` prelude inside the script body and let `mux_run(..., sudo=sudo)` handle privilege escalation at the tmux execution boundary.
- Verification result: `./.venv/bin/pytest tests/ -v` passed with 63/63 tests green.
