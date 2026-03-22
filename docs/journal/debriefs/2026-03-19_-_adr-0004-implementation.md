# ADR-0004 Implementation Debrief

**Date:** 2026-03-19
**Task:** Implement ADR-0004 (fork cherry-pick and poll hardening)

## Summary

Implemented all four phases of ADR-0004 across 4 commits. Added fleet discovery tools, SSH config parsing, project-level config search, and hardened the poll() tool against BUG-0001.

## Phase 1: hosts.py expansion

**Files changed:** `maestro/hosts.py`

- Added `RemoteCLI` enum (codex|gemini|claude) and `remote_cli` field on `HostConfig` with full hosts.yaml parsing.
- Added `_parse_ssh_config(alias)` for read-only SSH config discovery of a single host.
- Added `_list_ssh_config_hosts()` to enumerate all Host blocks in `~/.ssh/config`.
- Added `_find_hosts_config()` priority chain: `MAESTRO_HOSTS_PATH` → `MAESTRO_PROJECT_DIR/.maestro/hosts.yaml` → default. Skipped CWD search per ADR rationale.
- Updated `_load_hosts()` to call `_find_hosts_config()` as fallback and parse `remote_cli` from yaml.
- Added `os` and `logging` imports.

## Phase 2: new fleet tools

**Files changed:** `maestro/tools/fleet.py`

- Added `reconnect_host(host)`: tears down ControlMaster socket, sleeps 1s, warms up fresh connection. Uses existing `_teardown_connection` and `_warmup_connection` from transport.py.
- Added `list_ssh_hosts()`: calls `_list_ssh_config_hosts()`, cross-references with HOSTS to set `in_fleet` flag.
- Added `add_host(name, alias, ...)`: writes new entry to hosts.yaml, calls `init_hosts()` for hot-reload. Validates alias exists in SSH config (unless is_local). Tool description includes mandatory user approval language.
- Added `_teardown_connection` to transport imports, `Any` to typing imports.

## Phase 3: poll() hardening

**Files changed:** `maestro/tools/fleet.py`

- Replaced `asyncio.wait_for` blocking in `poll(wait>0)` with immediate return of HTTP endpoint redirect payload. MCP tool call returns instantly instead of occupying SSE session for up to N seconds.
- `poll(wait=0)` path completely unchanged — cooldown logic preserved.
- Updated docstring to explain BUG-0001 mitigation rationale.

## Phase 4: documentation

**Files changed:** `AGENTS.md` (new), `GEMINI.md` (updated), `TOOLS.md` (updated)

- Created AGENTS.md with build/test commands, code style, architecture overview, key patterns.
- Updated GEMINI.md with new tools (reconnect_host, list_ssh_hosts), HTTP polling pattern, tool quick reference table.
- Updated TOOLS.md with reconnect_host, list_ssh_hosts, add_host docs and rewritten poll docs explaining wait>0 redirect behavior.

## Test Results

All 54 tests pass (`pytest tests/ -v`). All modified Python files compile cleanly (`py_compile`).

## Decisions

- Kept `asyncio.sleep(1)` in `reconnect_host` between teardown and warmup to give the ControlMaster socket time to clean up.
- Used late imports in tool functions (`from maestro.hosts import ...`) to avoid potential circular import issues at module load time.
- `add_host` falls back to the repo-level `hosts.yaml` if `_find_hosts_config()` returns None, matching the existing default path.
