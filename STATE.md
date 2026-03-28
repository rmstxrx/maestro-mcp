# STATE.md — maestro-mcp

**Last Updated:** 2026-03-26

---

## Current Focus

**ADR-0007 landed (Phases 1–3).** Taxonomy cleanup, tmux multiplexer layer, and mux tools are deployed. Phase 4 (agent interop) is deferred pending a concrete use case.

### Recent Commits

```
3f4332a docs: add critical rule 9 — Claude.ai deferred tool loading
6dd4270 fix: neutralize mux tool docstrings for Claude.ai intent classifier
fb07303 fix: dispatch guard false positive on tmux commands, rename mux tools
63782e8 feat: ADR-0007 Phase 3 — persistent windows, mux tools, orchestra wiring
0265c62 feat: ADR-0007 Phase 2 — mux.py tmux multiplexer layer
15c364f refactor: ADR-0007 Phase 1 — taxonomy cleanup, split fleet/orchestra tools
```

### Tool Inventory (23 tools)

**Fleet (16):** `exec`, `script`, `read`, `write`, `transfer`, `status`, `reconnect_host`, `list_ssh_hosts`, `add_host`, `agent_status`, `gemini_sessions`, `mux_start`, `mux_read`, `mux_input`, `mux_stop`, `mux_list`.

**Orchestra (7):** `codex`, `gemini`, `claude`, `poll`, `read_output`, `tasks`, `prepare_relay`.

### Deployment (Hub)

| Component | Location |
|---|---|
| Repo (git clone) | `/volume2/docker/maestro/repo/` |
| Config (.env, hosts.yaml, ssh/, cloudflared/) | `/volume2/docker/maestro/config/` |
| Persistent state (oauth, ledger) | `/volume2/docker/maestro/state/` |
| Containers | `maestro` (python:3.12-slim) + `maestro-cloudflared` (Alpine + cloudflared) |
| Update workflow | `cd repo && git pull && docker compose up -d --build` |

### Fleet Topology

| Host | Role | Status |
|---|---|---|
| Hub | Hub (`is_local: true`), orchestration only | Docker, always-on |
| GPU-server | Compute leaf, agent dispatch target | GPU workstation, GPU workloads |
| Win-server | Compute leaf, agent dispatch target | RTX 5090, PowerShell |
| Macbook | Compute leaf, agent dispatch target | MacBook Pro M3 Max |
| Win-server-WSL | Compute leaf (proxy through Win-server) | WSL2 Ubuntu on Win-server |

## Active Branches

| Branch | Status |
|--------|--------|
| `main` | Active development. ADR-0007 Phases 1–3 + bug fixes landed. |

## Blockers

- None.

## What's Next

1. **ADR-0007 Phase 4 — Agent interop (deferred).** Infrastructure is in place (named windows, mux tools), but cross-agent observation needs deliberate design around coordination and scope. Not a checklist item — revisit when a concrete use case demands it.
2. **Stale items from previous cycles:**
   - Set `MAESTRO_DEFAULT_REPO` in `.env` to a real path (or remove the config field).
   - Delete stale remote branch `feat/adr-0004-0005-pin-rotation` if fully merged.
   - Delete old `task_registry.json` on Hub if present (in-memory registry handles HTTP result endpoint).

## Completed (recent)

- Output directory migrated: `~/.agent-orchestra/outputs/` → `~/.maestro/outputs/` on GPU-server. Old directory removed.
- Dispatch guard regex anchored to start-of-command (fixed tmux false positives).
- Mux tools renamed (`spawn`→`mux_start`, etc.) with neutral docstrings.
- Critical Rule 9 added to CLAUDE.md: Claude.ai deferred tool loading via Tool Search.
- 68/68 tests passing.
