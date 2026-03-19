# ADR-0005 Implementation: Host-Aware Agent Routing

**Date:** 2026-03-19
**Commit:** `feat(ADR-0005): host-aware agent routing — stdio local self-reference block`

## Task Summary

Implemented ADR-0005 to prevent local stdio agents (Claude Code, Codex CLI, Gemini CLI running on the hub) from routing local commands through Maestro's fleet tools when they have faster native tools available. Adds stdio client classification, dynamic MCP instructions, and a local self-reference guard on fleet I/O tools.

## Files Changed

- **maestro/client.py** — Added `STDIO_PROFILE`, `client_type`/`local_host` fields to `ClientContext`, `set_stdio_mode()` function, and stdio-aware `get_client_context()` that returns a stdio context when the flag is set.

- **maestro/tools/fleet.py** — Added `_check_local_self_reference()` at module level. Returns a descriptive JSON error when a stdio client targets the local host. Guard added as the first check in `exec`, `script`, `read`, and `write`. Not added to: `status`, `agent_status`, `codex`, `gemini`, `claude`, `poll`, `read_output`, `transfer`, `prepare_relay`, `reconnect_host`, `list_ssh_hosts`, `add_host`, `gemini_sessions`.

- **server.py** — Parses `--transport` from `sys.argv` at module level (before `FastMCP` construction). When `stdio`, calls `set_stdio_mode()` with the local host name. `_build_instructions()` now accepts a `transport` parameter: stdio mode generates instructions telling the agent where it is and which hosts are remote; HTTP mode keeps the existing compact format.

## How stdio Detection Works

1. `server.py` checks `sys.argv` for `--transport stdio` at module level, after `init_hosts()` populates `HOSTS`.
2. If stdio, it calls `set_stdio_mode(local_host_name=...)` which sets module-level flags in `client.py`.
3. `get_client_context()` checks `_STDIO_MODE` first — if set, returns a `ClientContext` with `client_type="stdio"` and the local host name, bypassing the HTTP contextvar entirely.
4. `_check_local_self_reference()` in fleet tools reads this context and blocks I/O tools targeting `is_local` hosts.

## Blocked vs Allowed Tools (stdio + local target)

| Blocked | Allowed |
|---|---|
| exec, script, read, write | status, agent_status, codex, gemini, claude, poll, read_output, transfer, prepare_relay, reconnect_host, list_ssh_hosts, add_host, gemini_sessions |

## Test Results

All 54 existing tests pass. No new tests needed — the guard is a simple conditional check with no new async paths.

## Design Decisions

- `ClientContext.client_type` defaults to `classification` via `__post_init__` for backward compatibility — existing HTTP contexts get `client_type` matching their classification without any caller changes.
- The guard uses `hasattr(ctx, 'client_type')` as a defensive check, though with the dataclass default this is always true.
- `sys.argv` parsing at module level is intentionally minimal (no argparse) — it only needs `--transport` before `FastMCP()` runs.
