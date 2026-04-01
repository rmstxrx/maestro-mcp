# STATE.md — maestro-mcp

**Last Updated:** 2026-04-01

---

## Current Focus

**ADR-0009 is implemented on `feat/adr-0009-tool-surface-refactor`.** The tool surface now matches the 11-tool target: renamed task/file/orchestration tools, tmux-only `run_task`, curl-prepared transfer helpers, and `read_task_output`.

### Recent Commits

```text
a1a512e feat: phase 3 — transfer_pull_file, transfer_push_file, read_task_output, task_result extraction
222da15 refactor: phase 2 — rename tools, merge service into run_task, unify exec through tmux
f1509a8 refactor: phase 1 — remove zombie tools (observe, steer, poll, gemini_sessions)
3f4332a docs: add critical rule 9 — Claude.ai deferred tool loading
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
| Containers | `maestro` + `maestro-cloudflared` |
| Update workflow | `cd repo && git pull && docker compose up -d --build` |

### Fleet Topology

| Host | Role | Status |
|---|---|---|
| Hub | `is_local: true`, orchestration container host | Docker, always-on |
| GPU-server | Compute leaf, agent dispatch target | GPU workstation |
| Win-server | Compute leaf, PowerShell/Windows-native target | GPU workstation |
| Macbook | Compute leaf, agent dispatch target | Laptop |
| Win-server-WSL | Bash-compatible leaf via Win-server | WSL2 Ubuntu |

## Active Branches

| Branch | Status |
|---|---|
| `feat/adr-0009-tool-surface-refactor` | Active implementation branch for the ADR-0009 tool surface refactor. |
| `main` | Stable baseline before ADR-0009 deployment. |

## Blockers

- None in the repo. Deployment to Hub and any AGENTS.md follow-up are separate steps.

## What's Next

1. Deploy the ADR-0009 branch to Hub and verify the live MCP tool list matches the 11-tool surface.
2. Update repo/root AGENTS guidance separately if the operator still wants the `read_task_output` / `stop_task` wording reflected there.
3. Exercise the staged pull/push flow end-to-end against a real remote host after deployment.

## Completed (recent)

- Removed zombie registrations: `observe`, `steer`, `poll`, `gemini_sessions`.
- Renamed the task/file/orchestration tools to the ADR-0009 surface.
- Merged `service` into `run_task(persistent=True)` and routed all `command=` execution through tmux + auto-promote.
- Added curl-prepared `transfer_pull_file`, `transfer_push_file`, and `read_task_output(full=True)` paths that keep file bytes out of MCP results.
- Split `task_result` into `maestro/task_result.py`.
