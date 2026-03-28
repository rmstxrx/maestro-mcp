# ADR-0007 Session: Taxonomy, Multiplexer Layer, and State Conventions

**Date:** 2026-03-25 / 2026-03-26
**Participants:** Rômulo + Claude (chat), Codex (3 dispatches)
**Duration:** ~4 hours across one continuous session

---

## What Happened

Designed and implemented ADR-0007 across four phases in a single session. The ADR addresses three long-standing problems: naming drift between "orchestrator"/"fleet"/"orchestra", SSH signal leaking (pkill killing ControlMaster), and scattered state directories.

### Taxonomy (decided interactively)

Locked the canonical terminology after philosophical discussion:

- **Maestro** — The system. Never say "orchestrator."
- **Orchestra** — AI agents + their coordination (dispatch, task ledger, scope prefix, output management). Musical terms for intelligence.
- **Fleet** — Physical/virtual machines, SSH transport, host topology. Logistical terms for infrastructure.

Key insight: the fleet exists independently of any agent activity. It's the concert hall, not the performers. Forcing it into the musical metaphor would obscure its nature as logistics infrastructure.

### Multiplexer Layer (designed interactively, implemented by Codex)

The SSH signal leaking problem led to the tmux multiplexer design. Critical discovery during design: **benchmarking showed zero overhead** (40ms raw SSH vs 39ms tmux-wrapped over SSH on the Hub→GPU-server path). This eliminated the "simplicity vs efficiency" trade-off entirely — tmux became the universal execution substrate, not an optional feature.

Design decisions:
- **Dedicated tmux server** (`-L maestro`) per host — full isolation from user's personal tmux
- **Ephemeral windows** for exec/script — signal isolation with self-cleanup
- **Persistent named windows** for agent dispatch — observable, attachable, configurable cleanup
- **Default stay** after command exits (remain-on-exit), optional auto-cleanup flag
- **Win-server PowerShell** bypasses tmux entirely; Win-server-WSL is the primary host for that machine
- **Window naming**: Maestro assigns names (`codex-{task_id[:8]}`), caller can provide optional label for manual spawns

### State Conventions (decided interactively)

- `~/.maestro/` on every host (like `~/.ssh/`)
- Hub (Hub): oauth, ledger, audit log, outputs
- Compute hosts: outputs only
- `~/.agent-orchestra/` abolished
- `task_registry.json` disk persistence deprecated — live state is the tmux session

### Misdirected Task Problem (identified and solved)

During discussion of task ledger evolution, identified that the **centralized task registry** was the root cause of the misdirected task bug (BUG-0001 variant). The Hub's in-memory registry was the source of truth for "what's running where?" — stale state, eviction races, and restart orphaning caused tasks to be misattributed between hosts. With tmux, each host's tmux server is the authority on its own live state. `list_windows(host)` queries the host directly.

## Implementation (4 commits, 3 Codex dispatches)

| Commit | Phase | Files | Tests | Agent |
|--------|-------|-------|-------|-------|
| `620af59` | ADR document | 1 | — | Manual |
| `15c364f` | Phase 1: Taxonomy split | 7 (+332/-269) | 59/59 | Codex ~10min |
| `0265c62` | Phase 2: mux.py core | 6 (+262/-12) | 63/63 | Codex ~7min |
| `63782e8` | Phase 3: Persistent windows + orchestra | 8 (+461/-21) | 68/68 | Codex ~11min |

All deployed to Hub. All smoke tested.

### Phase 1: Taxonomy cleanup
- `register_tools()` → split into `register_fleet_tools()` + `register_orchestra_tools()`
- Agent dispatch tools (codex, gemini, claude, poll, read_output, tasks, prepare_relay) moved from fleet.py to orchestra.py
- Output dir default changed to `~/.maestro/outputs`
- Taxonomy section added to CLAUDE.md

### Phase 2: mux.py core
- New module `maestro/mux.py` (168 lines): `configure_mux()`, `mux_run()`, `ensure_session()`, `_build_ephemeral_wrapper()`
- fleet.exec() and fleet.script() routed through `mux_run()` for all bash hosts
- PowerShell explicitly bypasses mux
- tmux added to Dockerfile
- Heredoc with single-quoted delimiter prevents command expansion

### Phase 3: Persistent windows + orchestra wiring
- 5 new mux functions: `mux_spawn`, `mux_capture`, `mux_send_keys`, `mux_kill_window`, `mux_list_windows`
- 5 new MCP tools in fleet.py: spawn, capture, send_keys, kill_window, list_windows
- Orchestra dispatch (`_orchestra_run_cli`) routed through `mux_spawn` with named windows (`codex-{task_id[:8]}`)
- `_orchestra_run_cli_raw` renamed to `_orchestra_run_cli_raw_ps` (PowerShell-only fallback)
- `TaskRegistryStore` disconnected in server.py (`task_store=None`)
- Base64 encoding for capture output to prevent format mangling

## Bugs Found

### Bug 1: Claude.ai MCP connector filters new tools
The 5 new Phase 3 tools (spawn, capture, send_keys, kill_window, list_windows) are registered server-side but invisible to Claude.ai's tool discovery. Same intent classification issue that previously affected `prepare_relay`. Tool names like "kill_window" and "send_keys" likely trigger the filter.

**Fix needed:** Rename tools to pass the connector filter. Same approach as `get_transfer_token` → `prepare_relay`.

### Bug 2: Dispatch guard false positive on tmux commands
The `_AGENT_CLI_PATTERNS` regex matches tmux commands containing agent window names. Example: `tmux capture-pane -t codex-10abf942 -p` trips the guard because "codex" + "-p" matches `\b(codex)\b.*-[pq]`.

**Fix needed:** Tighten regex to require agent name at command start, or exclude tmux commands.

## Decisions Made

1. Taxonomy: Maestro/Orchestra/Fleet — locked, documented in CLAUDE.md
2. tmux as universal substrate (not opt-in) — validated by benchmark
3. Dedicated `-L maestro` server per host — isolation over convenience
4. Win-server-WSL is primary; Win-server PowerShell is escape hatch
5. `~/.maestro/` on every host — like `~/.ssh/`
6. Task registry deprecated — tmux is live state, ledger is audit trail
7. Window naming: `{agent}-{task_id[:8]}` for orchestra, label or `spawn-{hex}` for manual
8. Configurable cleanup: windows stay by default (remain-on-exit), optional cleanup flag

## What's Next

See handoff: `docs/journal/handoffs/2026-03-26_-_adr-0007-phase-4-followup.md`
