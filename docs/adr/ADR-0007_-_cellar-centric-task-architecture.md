# ADR-0007: Cellar-Centric Task Architecture

**Date:** 2026-03-27  
**Status:** Accepted  
**Deciders:** Rômulo (fleet operator), Claude Chat (orchestrator/implementer)  
**Supersedes:** Portions of ADR-0003 (module decomposition), ADR-0006 (task ledger)  

---

## Context

Maestro's task execution model creates tmux sessions on remote hosts and observes them through ephemeral SSH channels. This produces five structural problems:

1. **Blind between probes.** Checking on a task is rediscovering, not monitoring. If a host reboots or a process crashes, Maestro learns only on the next manual probe.
2. **Two-system split.** Orchestra tasks (agent dispatches) have ledger entries and output files. Mux tasks (interactive sessions) have neither. No unified view of fleet activity exists.
3. **Cross-host retrieval failure.** If SSH drops mid-task, the output may be partial on the Cellar while the process continues on the remote host. The ledger records the dispatch but cannot recover the result.
4. **Fire-and-forget agents.** No ability to observe intermediate reasoning or steer agents mid-execution. A misread at minute two compounds silently for fifteen minutes.
5. **Compulsive monitoring.** The orchestrator compulsively polls running tasks — via `poll` (returning useless status) or `exec` (SSHing into hosts to inspect log files). Both waste tokens without producing actionable information.

These are not fixable individually. They share a root cause: the tmux session (the persistent substrate) lives on the remote host, while the observer (Maestro) lives on the Cellar. Observation requires crossing the network boundary every time.

---

## Decision

### The Inversion

All tmux sessions move from remote hosts to the Cellar. Every task Maestro executes becomes a tmux window on the Cellar's local tmux server. The command inside each window is an SSH session to the target host. Maestro observes, steers, and detects completion locally — no network crossing required for any of these operations.

```
Before: Cellar → SSH (ephemeral) → tmux on remote host → process
After:  Cellar → tmux on Cellar → SSH (inside tmux window) → process on remote host
```

### Core Principles

**Only Maestro creates tmux sessions.** Dispatched agents do not create tmux sessions on remote hosts. This is enforced architecturally — the codebase has no function that creates remote tmux sessions.

**Universal ledger tracking.** Every operation that touches a remote host — execution, file I/O, transfers — gets a ledger entry. The ledger is a recovery mechanism (transport failures are recoverable without re-running) and an audit trail ("what did we change on Apollyon today?").

**Timeouts are system policy.** No tool exposes a timeout parameter. Block thresholds, hard ceilings, and overtime flags are set in `MaestroConfig` by the fleet operator.

**Honest overtime accounting.** The caller declares `expected_runtime` — their estimate of how long the task will take. Maestro records it verbatim and flags the task as `overtime` at exactly that value. No hidden multipliers. The agent sees accurate feedback and learns to estimate better over time.

**Double-entry output residency.** Agent outputs exist on both the target machine (project history, indefinite retention) and the Cellar (replica, 90-day retention). Either copy can recover the other.

### Completion Detection

Each tmux window runs a wrapper script that signals completion via `tmux wait-for`:

```bash
#!/bin/bash
ssh {host} '{command}' | tee /output/{task_id}.txt; echo ${PIPESTATUS[0]} > /output/{task_id}.rc
tmux -L maestro wait-for -S "done-{task_id}"
```

Maestro's asyncio monitor blocks on the corresponding `tmux wait-for "done-{task_id}"` — a zero-CPU synchronization primitive that unblocks the instant the process exits. No polling, no sentinel file spinning.

### Agent Supervision

Dispatched agents run inside observable, steerable tmux windows. Two modes:

**One-shot** (default): Agent receives the prompt via CLI flag (`-p "prompt"`), runs autonomously. Steering is possible via keystroke injection but limited.

**Interactive**: Agent starts without a prompt, in its native interactive CLI. The orchestrator drives the conversation through alternating `observe` (read the pane) and `steer` (send keystrokes) calls. Multi-turn, responsive, adaptive — the conductor directing the musician in real time.

This is the core value proposition of the refactor. The tmux inversion exists so that the conductor can steer agents.

### Task Types and Timeout Model

| Type | Tool | Block threshold | Hard ceiling | Overtime |
|---|---|---|---|---|
| Execution | `run` | Profile-driven (5–15s) | 300s | At declared `expected_runtime` (default 15s) |
| Agent work | `dispatch` | 0s (always background) | 6h (configurable) | At declared `expected_runtime` (default 30m) |
| Service | `service` | 0s (always background) | None (indefinite) | 24h advisory nudge |

Three independent concerns: block threshold (UX), hard ceiling (safety), overtime (accountability). None lie to each other.

---

## Tool Surface

**23 tools → 13 tools (43% reduction).**

### Final Tool Set

**Fleet I/O (4):**

| Tool | Purpose | Ledger | Tmux |
|---|---|---|---|
| `run` | Execute a command or script on a host | Yes | Yes |
| `read` | Read a file from a host | Yes | No |
| `write` | Write a file to a host | Yes | No |
| `transfer` | SCP file to/from a host | Yes | No |

**Task Dispatch (2):**

| Tool | Purpose | Ledger | Tmux |
|---|---|---|---|
| `dispatch` | Start codex/gemini/claude (oneshot or interactive) | Yes | Yes |
| `service` | Start a long-running process (vLLM, Jupyter, etc.) | Yes | Yes |

**Task Lifecycle (5):**

| Tool | Purpose |
|---|---|
| `tasks` | Query the ledger. Fleet-wide visibility. Surfaces overtime flags. |
| `observe` | Capture live output of a running task (local pane, zero SSH cost). |
| `steer` | Send input to a running task (local send-keys, logged to output). |
| `stop` | Kill a task (kills tmux window → SSH → remote process). |
| `read_output` | Read completed task output from Cellar disk. |

**Infrastructure (2):**

| Tool | Purpose |
|---|---|
| `status` | Fleet health, agent availability, auto-reconnect. |
| `prepare_relay` | Ephemeral transfer/task-result token (1h TTL). |

### Consolidations

- `exec` + `script` → `run`. Single-line vs. multi-line is a formatting detail Maestro detects internally, not a tool boundary.
- `codex` + `gemini` + `claude` → `dispatch`. One code path for all guards.
- `mux_start` → absorbed. Every run/dispatch/service creates a tmux window.
- `mux_read` → `observe`. Works on any task, name signals intent.
- `mux_input` → `steer`. Name signals the Whiplash principle.
- `mux_stop` → `stop`. Works on any task.
- `mux_list` → absorbed into `tasks`. Task list IS the window list.
- `poll` → **removed**. The itch enabler. Structurally unnecessary.
- `reconnect_host` + `agent_status` → absorbed into `status`.
- `list_ssh_hosts`, `add_host`, `gemini_sessions` → **removed**. Admin tasks handled via `run`/`write`.

### Tool Signatures

```python
# Fleet I/O
run(host, command, cwd?, sudo?, expected_runtime?)
read(host, path, head?, tail?)
write(host, path, content, append?, sudo?)
transfer(host, direction, local_path, remote_path)

# Task Dispatch
dispatch(host, agent, prompt, working_dir, mode?, expected_runtime?,
         model?, reasoning_effort?, approval_mode?, context_files?,
         resume?, allowed_tools?)
service(host, command, label?, cwd?)

# Task Lifecycle
tasks(status?, type?, host?, last?)
observe(task_id, lines?)
steer(task_id, keys)
stop(task_id)
read_output(file_path, start_line?, max_lines?)

# Infrastructure
status()
prepare_relay()
```

### Safety Properties

- **Unified dispatch validation.** One `dispatch`, one code path for all guards (host validation, allowed_dirs, scope prefix, ledger recording).
- **`stop` refuses to kill the tmux server.** Validates target is a task window, not the maestro session.
- **`steer` logs everything.** Every keystroke appended to the task's output file. Complete audit trail.
- **`observe`/`steer` validate task ownership.** Accept task_id, not raw window names.
- **Agent CLI bypass enforcement.** `run` rejects raw `codex -p "..."` / `gemini -p "..."` commands.
- **No remote tmux creation.** Architecturally impossible — the capability does not exist in the code.
- **No caller-controlled timeouts.** System policy only.
- **Universal ledger.** All fleet operations tracked. `read`/`write`/`transfer` included.

---

## Module Impact

### `maestro/mux.py` — Major Rewrite

Replace remote-tmux wrappers (~280 lines) with local-tmux management (~150 lines):
- `create_task_window(task_id, host, command, tee?, interactive?)`
- `wait_for_completion(task_id)` — `tmux wait-for`
- `capture_pane(task_id, lines?)` — local, no SSH
- `send_keys(task_id, keys)` — local, relayed through SSH
- `kill_window(task_id)` — local, SSH dies with it
- `list_windows()` — one call, fleet-wide

### `maestro/tools/fleet.py` — Significant Reduction

~350 lines / 16 tools → ~200 lines / 8 tools (run, read, write, transfer, service, observe, steer, stop).

### `maestro/tools/orchestra.py` — Significant Reduction

~600 lines / 7 tools → ~350 lines / 5 tools (dispatch, tasks, read_output, status, prepare_relay).

`_auto_promote` simplifies to:

```python
async def _auto_promote(task_id, host, command, block_threshold, ...):
    create_task_window(task_id, host, command)
    monitor = asyncio.create_task(_monitor_task(task_id))

    if block_threshold == 0:
        return auto_promoted_response(task_id)
    if block_threshold < 0:
        return await monitor

    done, _ = await asyncio.wait({monitor}, timeout=block_threshold)
    return monitor.result() if done else auto_promoted_response(task_id)
```

### `maestro/config.py` — Minor

New fields:
- `output_retention_days: int = 90`
- `run_ceiling: int = 300`
- `dispatch_ceiling: int = 21600` (env: `MAESTRO_DISPATCH_CEILING`)
- `service_overtime_advisory: int = 86400`
- `max_tasks_per_host: int = 10` (env: `MAESTRO_MAX_TASKS_PER_HOST`)
- `default_expected_runtime_run: int = 15`
- `default_expected_runtime_dispatch: int = 1800`

### Task Ledger Schema

New fields on `TaskLedgerEntry`:
- `type: str` — "run" | "dispatch" | "service" | "read" | "write" | "transfer"
- `expected_runtime: int | None` — caller's declared estimate, recorded verbatim.
- `output_file_remote: str | None` — path on target host (dispatch only).
- `mode: str | None` — "oneshot" | "interactive" (dispatch only).

### Estimated Code Impact

~1,230 lines → ~700 lines. ~43% reduction.

---

## Edge Cases

**Eden (PowerShell).** Cellar-local tmux runs `ssh cellar-to-eden 'powershell ...'`. Wrapper, tee, wait-for are bash on Cellar. Eden never needs tmux. The inversion simplifies Eden handling.

**Container restart.** Tmux dies, SSH sessions terminate. Ledger marks running tasks as `orphaned`. `output_file_remote` enables future recovery.

**SSH drop mid-task.** Cellar tmux detects SSH exit. Wrapper captures exit code, signals wait-for. Monitor updates ledger as failed. Remote output path provides recovery.

**Interactive sessions.** `run host='apollyon' command='bash'` creates a tmux window with an SSH shell. Auto-promotes immediately. Interact via `observe`/`steer`.

**Agent supervision (one-shot).** Tmux window captures output via `tee` and accepts input via `steer`. Full transcript in the output file.

**Agent supervision (interactive).** Agent starts without prompt. Orchestrator sends first instruction via `steer`, observes response, steers corrections. Complete multi-turn transcript captured.

**Services.** Indefinite tmux window. `observe` for live output. `stop` for teardown. No output file by default (service logs are continuous). `tasks(type="service")` lists them.

**Concurrent limits.** Soft per-host limit (default 10, configurable). Warn, don't block.

---

## Implementation Phases

Each phase is independently deployable.

1. **New `mux.py` core.** Local-tmux primitives. Old functions kept as `_legacy_`. Tests.
2. **Wire `run`.** Merges exec + script. Local-tmux, universal ledger, output capture, 300s ceiling.
3. **Wire `dispatch` (one-shot).** Unified agent dispatch. Double-entry output. Overtime/ceiling model.
4. **Wire `dispatch` (interactive).** `mode='interactive'` path. Agent starts bare, orchestrator drives via `steer`/`observe`.
5. **Wire task lifecycle.** `observe`, `steer`, `stop`, `tasks` (absorbing poll + mux_list), `status` (absorbing reconnect_host + agent_status).
6. **Wire `service`.** Indefinite tmux windows. No ceiling. 24h overtime advisory.
7. **Wire `read`/`write`/`transfer` ledger tracking.** Audit records, no tmux.
8. **Cleanup.** Remove legacy code, old tools. Update CLAUDE.md, STATE.md, AGENTS.md. Commit ADR.

---

## What Is NOT Changing

- Transfer relay HTTP endpoints.
- OAuth and authentication.
- Client classification and profiles (block thresholds remain profile-driven).
- AGENT_SCOPE_PREFIX and AGENTS.md conduct rules.
- Task ledger persistence format (additive fields only).

---

## Consequences

**Positive:**
- Single source of truth for all fleet activity. One `tasks` call shows everything.
- Agent supervision enables mid-execution course correction. Feedback loops shrink from quarter-hours to minutes.
- 43% tool surface reduction. Less agent confusion, fewer wrong choices.
- 43% code reduction. Fewer bugs, easier maintenance.
- Universal ledger + output capture eliminates re-runs from transport failures.
- Honest overtime feedback enables calibration improvement over time.
- Eden handling simplifies — no more "does this host support tmux?" branching.

**Negative:**
- Every task requires an SSH session held open inside a tmux window. Resource usage scales with concurrent tasks. Mitigated by soft per-host limits.
- Container restart kills all active tasks. Mitigated by Docker restart policy and orphan recovery via ledger.
- Interactive agent mode requires the orchestrator to actively drive the conversation. Not all tasks benefit from supervision — one-shot remains the default for routine work.

**Risks:**
- `tmux wait-for` behavior on edge cases (window killed externally, tmux server crash) needs testing.
- SSH connection stability through long-running tmux windows (hours/days for services) needs validation.
- The exec+script→run merge changes a tool name that fleet agents reference. Migration requires updating CLAUDE.md and AGENTS.md before deployment.
