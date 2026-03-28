# ADR-0007 Clean Deployment Debrief

**Date:** 2026-03-28
**Operator:** Claude Code on Cellar bare metal

## Context

ADR-0007 (cellar-centric task architecture) was merged to `main` across 6 commits. The Docker image needed a clean `--no-cache` rebuild to ensure no stale cached layers.

## Verification Results

| Check | Result |
|---|---|
| Git log matches expected ADR-0007 commit sequence | PASS |
| No legacy mux imports in fleet.py | PASS |
| No legacy mux imports in orchestra.py | PASS |
| `_mux_legacy.py` deleted | PASS |
| mux.py has no legacy re-exports | **FAIL** (fixed) |
| `_record_ledger_entry` accepts `status` param | PASS |
| `server.py` calls `configure_mux()` bare | PASS |
| Tool surface is 13 tools (no legacy) | PASS |
| All modules compile | PASS |

## Issue Found and Fixed

**`maestro/mux.py` — dead legacy code in `configure_mux`**

The `configure_mux` function still accepted `**legacy_kwargs` and referenced `configure_mux_legacy()`, but `_mux_legacy.py` was deleted in Phase 8. The dead code path would crash if anyone passed legacy kwargs. Since `server.py` calls `configure_mux()` bare, it didn't blow up at runtime, but the signature was misleading and the reference was a latent error.

Fix: removed `**legacy_kwargs`, the docstring mentioning legacy forwarding, and the `configure_mux_legacy` call. Committed as `a33ad67`.

## Deployment

1. `docker compose build --no-cache` — clean rebuild of both maestro and cloudflared images.
2. `docker compose up -d --force-recreate` — required because initial `up -d` reused running containers instead of recreating from new images.
3. SSH host keys re-accepted for all 5 hosts (cellar, apollyon, eden, judas, eden-wsl).
4. All tunnel connections re-established (4 QUIC connections to Cloudflare GIG PoPs).

## Validation

- OAuth discovery endpoint: responding correctly.
- Tool surface: exactly 13 tools registered (run, read, write, transfer, status, observe, steer, stop, service, dispatch, read_output, prepare_relay, tasks).
- No legacy tools present (exec, script, codex, gemini, claude, poll, mux_*, reconnect_host, list_ssh_hosts, add_host, agent_status, gemini_sessions — all absent).
- Fleet SSH connectivity: all 5 hosts responding.
- Remote MCP validation: requires fresh Claude.ai conversation (old session invalidated by container recreation).

## Notes

- The dev path (`/home/rmstxrx/Development/maestro-mcp`) and deploy path (`/volume2/docker/maestro/repo`) are the same repo via symlink (same inodes).
- `docker compose` must be run with `--project-directory /volume2/docker/maestro/repo` when CWD resolves through the symlink, otherwise `../config/.env` resolves incorrectly.
- Two uncommitted infrastructure changes exist in the working tree (healthcheck in docker-compose.yml, watchdog in cloudflared-entrypoint.sh) — left uncommitted per scope.
