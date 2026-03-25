# ADR-0007 — Taxonomy, Multiplexer Layer, and State Conventions

**Status:** Proposed  
**Date:** 2026-03-25  
**Supersedes:** Portions of ADR-0003 (module naming), ADR-0006 (task registry as live state)

---

## Context

Three related problems have emerged as Maestro matures:

1. **Naming drift.** "Orchestrator" and "fleet" are used interchangeably in conversation and docs. The code has agent dispatch tools inside `fleet.py` and task machinery called "orchestra." There is no authoritative taxonomy.

2. **Signal leaking.** Commands like `pkill` executed via `ssh host "pkill foo"` can propagate signals up the process tree and kill the SSH ControlMaster. There is no process isolation between Maestro's SSH channel and the commands it runs. More broadly, there is no persistent execution context on hosts — every command is a one-shot SSH invocation with no ability to observe, interact with, or attach to running processes.

3. **Scattered state.** Maestro's footprint on hosts is split across `~/.maestro/` (hub only), `~/.agent-orchestra/outputs/` (legacy name, inconsistent across hosts), and `~/Development/General/tmp/` (scratch). There is no convention for where Maestro places its data on a host.

## Decisions

### D-1: Taxonomy

Three domains, clear boundaries:

| Domain | Term | Scope | Rule |
|--------|------|-------|------|
| **System** | **Maestro** | The MCP server and everything it governs | Always use the proper name. Never say "orchestrator." |
| **Intelligence** | **Orchestra** | AI agents (Codex, Gemini, Claude Code) and their coordination: dispatch, scope prefix, task ledger, output management | Musical terms for intelligence. |
| **Infrastructure** | **Fleet** | Physical and virtual machines, SSH transport, host topology, file operations | Logistical terms for infrastructure. |

**The principle:** Musical terms for intelligence. Logistical terms for infrastructure. Maestro conducts both.

**The metaphor:** A symphony orchestra performs in a concert hall. The Maestro conducts the Orchestra (the performers). The Fleet is the concert hall — it exists independently of any performance. The Maestro bridges both domains.

**Code implications:**
- `tools/fleet.py` contains only infrastructure tools: `exec`, `script`, `read`, `write`, `transfer`, `status`, `add_host`, `reconnect_host`, `list_ssh_hosts`, `agent_status`.
- `tools/orchestra.py` contains all intelligence tools: `codex`, `gemini`, `claude`, `poll`, `read_output`, `tasks`, `prepare_relay`, plus task registry, task ledger, auto-promote logic, scope prefix, and output management.
- Agent dispatch functions currently in `fleet.py` move to `orchestra.py`.

**Documentation and conversation:** All docs, comments, commit messages, and session logs must use the canonical terms. A glossary is added to CLAUDE.md.

### D-2: tmux Multiplexer Layer (`mux.py`)

Every command Maestro executes on a host runs inside a tmux session. tmux is the **universal execution substrate**, not an optional feature.

#### Rationale

Benchmarking on the Cellar → Apollyon path (SSH with ControlMaster) shows zero measurable overhead:

| Method | Avg latency (10 runs) |
|--------|-----------------------|
| Raw SSH `echo hello` | 40ms |
| SSH + tmux file-capture | 39ms |
| SSH + setsid (isolation only) | 30ms |

SSH round-trip latency dominates completely. The tmux machinery is free.

#### Architecture

```
fleet.py / orchestra.py
         │
         ▼
      mux.py          ← NEW: multiplexer abstraction
      │      │
      ▼      ▼
transport.py  local.py   (unchanged — SSH and local execution)
```

`mux.py` sits between the tool layer and the transport layer. It does not replace `transport.py` — it uses it. SSH still handles connections. tmux handles isolation and persistence.

#### tmux Server

Each host runs a **dedicated tmux server** accessed via `-L maestro`:

```bash
tmux -L maestro new-session -d -s main    # Create the Maestro server
tmux -L maestro ls                         # List sessions
tmux -L maestro attach -t main             # Manual attachment (escape hatch)
```

The `-L maestro` flag spawns a separate tmux server process with its own socket (at tmux's default location, typically `/tmp/tmux-{UID}/maestro`). This provides:

- **Full isolation** from the user's personal tmux sessions.
- **No namespace collisions** — Maestro sessions cannot conflict with user sessions.
- **Clean teardown** — killing the Maestro tmux server affects nothing else.

Manual attachment is an escape hatch, not the primary interface. **Tools handle observation** — `capture`, `list_windows`, and `send_keys` are the designed interaction path.

#### Execution Modes

**Ephemeral execution** (for `exec`, `script`):

```
1. Ensure maestro tmux session exists on host
2. Generate unique run ID
3. tmux new-window: run command, redirect stdout/stderr to /tmp/maestro_{id}.out,
   write exit code to /tmp/maestro_{id}.rc
4. Poll for .rc file (local sleep loop, ~10ms intervals)
5. Read .out and .rc
6. Clean up temp files
7. Return formatted result
```

All of this happens inside a **single SSH invocation** — the entire sequence is a bash script piped through SSH. No extra round trips.

The command runs in its own tmux window, in its own process group. Signals cannot propagate to the SSH ControlMaster or to other windows. After completion, the window self-destructs.

**Persistent execution** (for long-running processes, dev servers, agent sessions):

```
1. Ensure maestro tmux session exists on host
2. Create a named window: tmux new-window -t maestro -n {name} '{command}'
3. Return handle (host, window name)
4. Window persists until explicitly killed or process exits
```

Persistent windows enable:
- **Observation**: capture the current screen content of any named window.
- **Interaction**: send keystrokes to a running process.
- **Agent interop**: Agent A starts a dev server; Agent B captures its output.
- **Survival**: processes outlive SSH connections and even Maestro restarts.

#### API Surface

```python
# Lifecycle
async def ensure_session(host: str) -> bool
async def destroy_session(host: str) -> bool

# Ephemeral (replaces direct _ssh_run / _local_run for commands)
async def run(host: str, command: str, timeout: int = 300) -> str
async def run_script(host: str, script: str, timeout: int = 300) -> str

# Persistent
async def spawn(host: str, name: str, command: str, cwd: str | None = None) -> str
async def send_keys(host: str, name: str, keys: str) -> str
async def capture(host: str, name: str, lines: int = 50) -> str
async def kill_window(host: str, name: str) -> str

# Discovery
async def list_windows(host: str) -> list[dict]
```

#### Integration with existing tools

`fleet.exec()` changes minimally:

```python
# Before:
raw = await _ssh_run(host, [_wrap_command(cfg, command, cwd, sudo)], timeout=timeout)

# After:
raw = await mux.run(host, _wrap_command(cfg, command, cwd, sudo), timeout=timeout)
```

Auto-promote continues to work — it wraps `mux.run()` just as it wraps `_ssh_run()` today. The difference is that promoted tasks can optionally become persistent windows instead of orphaned background processes.

#### Local host (Cellar)

For the hub (`is_local: true`), `mux.py` runs tmux commands directly (via `local.py`) instead of via SSH. Same API, different transport — consistent with the existing `local.py` / `transport.py` split.

#### Eden (Windows)

tmux is not available on Windows. **Eden-WSL is the primary fleet host for the Eden machine.** It runs tmux natively, has full bash, and can call Windows executables through WSL interop (`/mnt/c/...`, `.exe` invocations).

The direct PowerShell SSH entry (`eden`) remains in `hosts.yaml` as a **limited-access escape hatch** for cases that specifically require native PowerShell. It does not participate in the tmux substrate — commands sent to `eden` directly bypass mux and use raw SSH, as today.

No `mux_via` routing concept is needed. Every host either has tmux and participates fully, or it doesn't.

### D-3: State Directory Conventions

`~/.maestro/` is Maestro's footprint on every fleet host, analogous to `~/.ssh/`.

#### Hub (Cellar)

```
~/.maestro/
├── oauth_state.json      # OAuth client/token persistence
├── task_ledger.json      # Audit trail (append-only, 30-day auto-prune)
├── audit.log             # Server audit log
└── outputs/              # Agent output files generated on hub
```

#### Compute hosts (Apollyon, Eden-WSL, Judas)

```
~/.maestro/
└── outputs/              # Agent output files for tasks dispatched to this host
```

The tmux socket lives at tmux's default location for named servers (`/tmp/tmux-{UID}/maestro`). This is managed by tmux itself and does not need to be in `~/.maestro/`.

#### Abolished

- **`~/.agent-orchestra/`** — Legacy name. All contents migrate to `~/.maestro/outputs/`.
- **`task_registry.json`** — Live task state is the tmux session. The in-memory registry may still exist for the transition period but is no longer persisted to disk.

#### Scratch files

Agent scratch/temp files continue to go in `~/Development/General/tmp/` on compute hosts (per existing convention). `~/.maestro/` is for Maestro's own managed state, not agent working files.

### D-4: Task Ledger Evolution

The task ledger (`~/.maestro/task_ledger.json`) is retained as an **audit trail and history log**. It records every dispatched task with timestamps, agent, host, status, and outcome.

However, the ledger is no longer the source of truth for **live task state**. That role transfers to the tmux session. This solves the **misdirected task problem**: currently, all live state is centralized in the Cellar's `TASK_REGISTRY`. Polling "what's running on Apollyon?" queries the Cellar's memory, not Apollyon. Registry eviction, restarts, and timing races cause tasks to be misattributed between hosts or lost entirely. With tmux, the host itself is the authority on its own live state.

| Question | Before (ADR-0006) | After (ADR-0007) |
|----------|-------------------|-------------------|
| What's running right now? | `task_registry.json` | `tmux -L maestro list-windows` |
| What happened in the past? | `task_ledger.json` | `task_ledger.json` (unchanged) |
| How do I observe a running task? | `read_output` + file tailing | `mux.capture(host, name)` |
| How do I stop a running task? | Kill the OS process by PID | `mux.kill_window(host, name)` |

The `poll` tool continues to query the ledger for historical status. A new tool (or enhancement to `poll`) queries tmux for live state.

## Implementation Plan

### Phase 1: Taxonomy cleanup
1. Move agent dispatch tools from `fleet.py` to `orchestra.py`.
2. Update CLAUDE.md, STATE.md, and all docstrings with canonical glossary.
3. Rename `~/.agent-orchestra/outputs/` → `~/.maestro/outputs/` on all hosts.
4. Update `MAESTRO_ORCHESTRA_OUTPUT_DIR` default to `~/.maestro/outputs`.

### Phase 2: mux.py core
1. Implement `mux.py` with `ensure_session`, `run`, `run_script`.
2. Wire `fleet.exec()` and `fleet.script()` through `mux.run()`.
3. For hosts without tmux (Eden/PowerShell), `mux.run()` falls back to raw SSH (current behavior).
4. Tests: verify signal isolation (pkill inside tmux does not kill ControlMaster).

### Phase 3: Persistent windows + new tools
1. Implement `spawn`, `capture`, `send_keys`, `kill_window`, `list_windows`.
2. Expose as MCP tools (likely in `fleet.py` since they're infrastructure).
3. Wire orchestra dispatch to use persistent windows for agent sessions.
4. Deprecate `task_registry.json` persistence.

### Phase 4: Agent interop
1. Design naming conventions for agent windows (e.g., `codex-{task_id_short}`).
2. Enable agents to discover and observe each other's windows.
3. Document interop patterns in AGENTS.md.

## Consequences

**Positive:**
- Signal isolation eliminates the pkill/ControlMaster kill class of bugs entirely.
- **Eliminates misdirected task confusion.** The current architecture centralizes all live task state on the Cellar (`TASK_REGISTRY` in-memory, `task_registry.json` on disk). When polling or querying "what's running on host X?", the answer comes from the Cellar's registry, not from host X. Registry eviction, Maestro restarts, and timing races cause tasks to be misattributed or lost. With tmux, live state is **distributed** — each host's tmux server is the source of truth for what's running on that host. `list_windows(host="apollyon")` queries Apollyon directly. A pane either exists on that host or it doesn't. The centralized ledger remains as an audit trail ("what happened last week?"), but the live question ("what's happening right now?") goes to the host itself.
- Consistent taxonomy reduces cognitive load in docs, conversation, and code navigation.
- `~/.maestro/` convention makes fleet-wide cleanup and auditing trivial.
- Persistent windows unlock agent interop — a qualitative capability gain.
- Zero performance cost (benchmarked).

**Negative:**
- tmux becomes a hard dependency on all primary fleet hosts (Linux/macOS). Must be pre-installed.
- Eden (PowerShell) does not participate in the tmux substrate; Eden-WSL is the primary entry point for that machine.
- Agent dispatch tools moving from `fleet.py` to `orchestra.py` changes import paths (one-time migration).

**Risks:**
- tmux server crashes on a host would affect all running Maestro tasks on that host. Mitigation: `ensure_session` validates server health before every operation.
- File-based output capture (`/tmp/maestro_*.out`) creates temp file debris if Maestro crashes mid-execution. Mitigation: startup cleanup sweep + unique prefixed filenames.
