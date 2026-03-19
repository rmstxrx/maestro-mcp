# Maestro MCP — Agent Developer Guide

Guide for AI coding agents (Codex, Claude Code, Gemini) working on this codebase.

## Build & Test

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Syntax check (fast, no runtime deps)
python -m py_compile maestro/hosts.py maestro/tools/fleet.py

# Run tests
pytest tests/ -v

# Run server (stdio mode for MCP)
python server.py --transport stdio

# Run server (HTTP mode, requires MAESTRO_ISSUER_URL)
python server.py --transport streamable-http --port 8222
```

## Code Style

- **Imports:** `from __future__ import annotations` at top of every module. stdlib → third-party → local, separated by blank lines.
- **Type annotations:** Modern union syntax (`str | None`, `list[str]`), not `Optional[str]` or `List[str]`.
- **Formatting:** 4-space indent. No trailing whitespace. Single blank line between functions, two before top-level classes.
- **Naming:** `_private_function` for internal helpers, `UPPER_CASE` for module constants, `lower_case` for local variables.

## Architecture

```
server.py              ← FastMCP entry point, OAuth setup, wiring
maestro/
  config.py            ← MaestroConfig (frozen dataclass, from_env)
  hosts.py             ← Fleet topology: HostConfig, HOSTS registry, command helpers
  transport.py         ← SSH ControlMaster lifecycle, _ssh_run, _scp_run, retries
  local.py             ← Zero-overhead local execution (is_local: true hosts)
  relay.py             ← HTTP file transfer relay (push/pull/task results)
  client.py            ← Client context detection (remote/local/lan profiles)
  oauth_state.py       ← Atomic JSON persistence for OAuth state
  tools/
    fleet.py           ← All MCP tools (fleet + orchestra) registered here
    orchestra.py        ← Agent dispatch helpers, task registry, auto-promote
```

## Key Patterns

### Auto-Promote (block_timeout)
Execution tools try to finish within `block_timeout` seconds. If they don't, the task is shielded into `TASK_REGISTRY` and a `task_id` is returned. The caller uses `poll()` or the HTTP endpoint to retrieve results.

### ControlMaster Lifecycle
SSH connections use OpenSSH ControlMaster multiplexing. `_warmup_connection()` opens the master, `_teardown_connection()` closes it, `_check_control_master()` probes liveness. **Never replace this with asyncssh** — it breaks ProxyJump and requires reimplementing SSH config parsing.

### Late-Bound configure_* Pattern
`transport.py` and `orchestra.py` use a `configure_*()` function called at startup to inject dependencies (config, hosts, locks). This avoids circular imports while keeping modules testable.

### Tool Registration
All tools are registered inside `register_tools(mcp, config)` in `fleet.py`. The function receives a FastMCP instance and the global config. Tools are closures that capture `config` from the outer scope.

## Common Pitfalls

- **Python default parameters are evaluated at definition time.** Constants used as defaults must be defined before the functions that reference them.
- **hosts.yaml is gitignored.** Use `hosts.example.yaml` as a template.
- **Don't kill the Maestro process via Maestro tools** — it terminates the MCP connection with no recovery path.
