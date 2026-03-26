# ADR-0007 Phase 3 Persistent Windows

## Summary

Implemented persistent named tmux windows in `maestro/mux.py`, exposed the new mux management tools in `maestro/tools/fleet.py`, routed orchestra CLI dispatch through mux with a PowerShell raw-SSH fallback, disconnected task-registry disk persistence in `server.py`, updated `CLAUDE.md`, and verified the full test suite.

## Files Changed

- `maestro/mux.py` — Added `_build_spawn_wrapper()`, `mux_spawn()`, `mux_capture()`, `mux_send_keys()`, `mux_kill_window()`, `mux_list_windows()`, and the raw-output helper used for pane/window inspection.
- `maestro/tools/fleet.py` — Imported the new mux helpers, added tmux-host/window validation, and registered the `spawn`, `capture`, `send_keys`, `kill_window`, and `list_windows` MCP tools after the existing fleet tool set.
- `maestro/tools/orchestra.py` — Renamed the old raw runner to `_orchestra_run_cli_raw_ps()`, routed bash-host dispatch through `mux_run()` / `mux_spawn()`, and assigned persistent window names of the form `{agent}-{task_id[:8]}` for Codex, Gemini, and Claude.
- `server.py` — Stopped loading or wiring `TaskRegistryStore`, leaving task registry persistence disabled while keeping the in-memory registry and HTTP task lookup intact.
- `CLAUDE.md` — Documented the new mux tools and removed stale references to `task_registry.json` persistence from the architecture/state notes.
- `tests/test_mux.py` — Added coverage for named spawn wrapper generation and tmux window list parsing.
- `tests/test_primitives.py` — Added regression coverage for mux-backed orchestra dispatch on bash hosts and PowerShell fallback dispatch.

## Decisions And Surprises

- Kept the new fleet mux tools unavailable on PowerShell hosts, matching the ADR’s rule that direct PowerShell SSH remains an escape hatch outside the tmux substrate.
- Used a small base64-marked wrapper in `mux.py` for `capture` and `list_windows` so empty output can be distinguished from the transport layer’s `[no output]` formatter without changing `transport.py` or `local.py`.
- Verification result: `.venv/bin/pytest tests/` passed with 68/68 tests green.
