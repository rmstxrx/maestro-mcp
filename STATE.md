# DORMANT — Maestro v1 (maestro-mcp) superseded by Maestro v2

> **This repo is the archived v1 of the Maestro orchestrator. Active
> development has moved to `~/Development/maestro/` (v2).**
>
> Dormant as of: 2026-04-14.

## Where development moved

| Asset | Current home |
|-------|--------------|
| Active Maestro source | `~/Development/maestro/` (v2 — see its STATE.md) |
| Production deployment | Cellar, container `maestro-v2`, port 8222, tunnel `maestro.rmstxrx.dev` |
| Deploy repo on Cellar | `/volume2/docker/maestro-v2/repo/` |
| v1 container | Archived, not running |

The content below describes maestro-mcp (v1) as of 2026-04-01. Preserved for
reference — the 11-tool surface, decision trees, and ADR-0009 design still
read as a coherent snapshot of v1's operating model, and some of it carried
forward into v2. Do not develop against this repo.

---

# STATE.md — maestro-mcp (v1, historical)

**Last Updated:** 2026-04-01

---

## Current Focus

**ADR-0009 landed and deployed.** The 11-tool surface is live on Cellar, verified across all fleet hosts. Full smoke test passed: transfer round-trips across 4 hosts (3 OSes), tmux auto-promote, graceful stop, persistent services, read_task_output with full= curl mode.

### Recent Commits

```text
1e20e1c Merge feat/adr-0009-tool-surface-refactor: 11-tool surface refactor
de1550d docs: phase 4 — rewrite CLAUDE.md, STATE.md for ADR-0009
a1a512e feat: phase 3 — transfer_pull_file, transfer_push_file, read_task_output, task_result extraction
222da15 refactor: phase 2 — rename tools, merge service into run_task, unify exec through tmux
f1509a8 refactor: phase 1 — remove zombie tools (observe, steer, poll, gemini_sessions)
0a2b3f8 docs: ADR-0009 — tool surface refactor specification
```

### Tool Inventory (11 tools)

**File I/O (4):** `read_file`, `write_file`, `transfer_pull_file`, `transfer_push_file`

**Task Lifecycle (4):** `run_task`, `stop_task`, `current_tasks`, `read_task_output`

**Orchestration (2):** `dispatch_agent`, `orchestra_status`

**Infrastructure (1):** `prepare_relay`

### Deployment (Hub)

| Component | Location |
|---|---|
| Repo (git clone) | `/volume2/docker/maestro/repo/` |
| Config (.env, hosts.yaml, ssh/, cloudflared/) | `/volume2/docker/maestro/config/` |
| Persistent state (oauth, ledger, task output) | `/volume2/docker/maestro/state/` |
| Container | `maestro` (python:3.12-slim) |
| Tunnel | Host-native cloudflared systemd service |
| Update workflow | `cd repo && git pull && docker compose build --no-cache && docker compose up -d --force-recreate` |

### Fleet Topology

| Host | Role | Status |
|---|---|---|
| Cellar (Hub) | `is_local: true`, Maestro container host | Docker, always-on |
| Apollyon | Compute leaf, Maestro dev repo, agent dispatch target | DGX Spark |
| Eden | Windows-native leaf | RTX 5090, PowerShell |
| Eden-WSL | Bash-compatible leaf via Eden | WSL2 Ubuntu |
| Judas | Compute leaf, agent dispatch target | MBP M3 Max |

## Active Branches

| Branch | Status |
|---|---|
| `main` | Active. ADR-0009 merged and deployed. |

## Blockers

- None.

## What's Next

1. Clean up stale `feat/adr-0009-tool-surface-refactor` branch after confirming no regressions.
2. Monitor staged file cleanup (/tmp/maestro/staged/) TTL behavior over the next few days.
3. Consider whether `/tasks/{id}/result` HTTP endpoint is still needed now that `read_task_output` covers the use case via MCP.

## Completed (recent)

- **ADR-0009 full implementation** — 14→11 tools, all phases deployed and verified.
- Removed zombie tools: `observe`, `steer`, `poll`, `gemini_sessions`.
- Renamed all tools to category+action convention (_file, _task, _agent).
- Merged `service` into `run_task(persistent=True)`.
- Unified all execution through tmux + auto-promote. No more raw SSH blocking.
- Added curl-prepared `transfer_pull_file`, `transfer_push_file` (files never in MCP context).
- Added `read_task_output` with preview/tail/head/full modes.
- `stop_task(graceful=True)` sends SIGINT before killing.
- Extracted `task_result` to its own module.
- `current_tasks` no longer exposes container-internal paths.
- AGENTS.md updated on all fleet hosts (rules 10-12).
- CLAUDE.md rewritten with quick reference card, decision trees, Cellar/Maestro identity callout.
- 62/62 tests passing.
