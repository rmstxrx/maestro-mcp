# ADR-0009 — Relay-Only Data Channel

**Status:** Proposed  
**Date:** 2026-03-29  
**Supersedes:** Portions of ADR-0007 (exec/read/write tool semantics)  
**Reverses:** ADR-0008 (observe/steer deprecation — reinstated as control-plane tools)  
**Author:** Claude (strategist) + Rômulo (architect)

---

## Context

ADR-0007 established cellar-centric task architecture with Hub-local tmux
execution, reducing the tool surface from 23 to 13. However, persistent
operational friction remains in three areas:

1. **Escaping hell.** The `run` tool's `command` parameter carries arbitrary
   shell payloads — including multi-line scripts, heredocs, nested quotes,
   and variable expansions. `mux.py` contains two separate wrapper builders
   (`_build_wrapper` and `_build_script_wrapper`, ~115 lines combined) that
   attempt to safely wrap these through multiple layers of `shlex.quote` and
   SSH escaping. Failures are frequent and hard to diagnose.

2. **Blocking risk.** Both `run` (inline output return) and `read` (file
   content return) carry payload *back* through the MCP response channel.
   Large outputs or slow commands block the Claude.ai UI, sometimes for
   minutes. The auto-promote mechanism mitigates this for long-running tasks
   but short commands that produce unexpectedly large output still block.

3. **Non-uniform interaction patterns.** Simple commands go through `run`,
   file reads through `read`, file writes through `write`, large transfers
   through `prepare_relay` + HTTP. Each has different escaping rules,
   different size limits, and different failure modes. This cognitive overhead
   compounds across a conversation.

### Root Cause

The exec channel (MCP tool parameters and return values) is being used as
both a **control channel** and a **data channel**. These concerns must be
separated.

## Decision

**The exec channel becomes a pure control channel. The HTTP relay becomes the
sole data channel. No exceptions.**

### Core Principle

> Exec is an interrupt line — it signals "go." The relay is the data bus.
> The exec channel never carries payload in, and never carries payload out.

This is the filesystem-as-protocol insight from ADR-0002 applied to the
Claude↔host boundary: structural coupling to the filesystem, not to content.

### Lifecycle of Every Task

```
1. GENERATE  — Claude writes the script in the sandboxed container
2. PUSH      — Relay pushes script to /tmp/maestro/inbox/<id>.sh on host
3. EXEC      — Maestro triggers: tmux wraps execution with tee to outbox
4. OBSERVE   — Relay pulls /tmp/maestro/outbox/<id>.out (partial or final)
5. STOP      — kill via tmux window (if needed)
```

The exec template is **fixed and universal**:

```bash
bash /tmp/maestro/inbox/<id>.sh \
  > /tmp/maestro/outbox/<id>.out 2>&1
echo $? > /tmp/maestro/outbox/<id>.rc
```

That is the *only* thing the exec channel ever carries. No heredocs, no
inline scripts, no command parameters carrying payload.

### Tmux Role

Tmux remains as the **execution wrapper** — it provides session persistence,
multiplexing, and process lifecycle management. What changes is that tmux
no longer receives commands through inline parameters built by complex
wrapper functions. Instead, it always executes the same fixed template
pointing to a staged script file.

`_build_wrapper` and `_build_script_wrapper` in `mux.py` collapse into a
single ~10-line function.

### Services

Services follow the same pattern but without the `.rc` sentinel (they don't
terminate naturally). The script in the inbox starts the service; output is
tee'd to the outbox for bulk retrieval via relay-pull. Live monitoring uses
`observe` (tmux pane capture) for the current screen state.

### Staging Directories

On each host:

```
/tmp/maestro/inbox/    — scripts pushed by relay, executed by tmux
/tmp/maestro/outbox/   — stdout/stderr captured by tee, pulled by relay
```

Retention: cron or cleanup hook. Default: purge files older than 1 hour.
The container has already pulled results by then.

### Task ID Format

Timestamp-based with collision suffix: `YYYYMMDD-HHmmss-<hex4>`

Example: `20260329-143022-a3f1`

Provides chronological ordering, human readability, and uniqueness.

## Tool Surface Changes

### Removed (4 tools)

| Tool | Reason |
|------|--------|
| `run.command` param | Payload no longer transits exec channel |
| `read` | Replaced by relay-pull |
| `write` | Replaced by relay-push |
| `transfer` | Subsumed by relay push/pull |

Note: `read_output` is also removed — subsumed by relay-pull of outbox
files and tmux `observe` for live state.

### Retained (9 tools)

| Tool | Change |
|------|--------|
| `exec` | **Renamed from `run`.** Accepts only: `host`, `task_id`, `cwd`, `sudo`. No `command` parameter. Script must be pre-staged via relay. |
| `observe` | **Reinstated (reverses ADR-0008).** Captures live tmux pane state (~50 lines). Control-plane tool — low payload, used to inspect dispatched agents and services mid-run. Not a data channel. |
| `steer` | **Reinstated (reverses ADR-0008).** Sends keystrokes to a running task's tmux pane. Essential for interacting with dispatched agents (approval prompts, Ctrl+C, input). Pure control signal. |
| `stop` | Unchanged — kills tmux window by task_id |
| `status` | Unchanged — fleet health check |
| `tasks` | Unchanged — ledger query |
| `dispatch` | Unchanged — agent dispatch (builds CLI, uses tmux) |
| `service` | Adapted — script pre-staged via relay, same exec template |
| `prepare_relay` | Unchanged — issues ephemeral bearer tokens |

### Control Plane vs. Data Plane

The 9 retained tools split cleanly into two categories:

**Control-plane tools** (low-payload signals, transit MCP inline):
- `exec` — trigger execution of a pre-staged script
- `observe` — capture ~50 lines of live tmux pane state
- `steer` — send keystrokes to a running process
- `stop` — kill a task's tmux window
- `status` — fleet connectivity probe
- `tasks` — ledger query (metadata only)
- `prepare_relay` — issue auth token

**Data-plane tool** (bulk payload, transit HTTP relay):
- Relay push/pull via `curl` in the container's `bash_tool`

`dispatch` and `service` straddle both: they trigger execution (control)
but under ADR-0009, their scripts are pre-staged via relay (data).

The key invariant: **no tool parameter or return value ever carries more
than ~50 lines of content.** Bulk data always flows through the relay.

### Caller Workflow (Claude in claude.ai)

```
# 1. Write script locally
create_file("/home/claude/task.sh", "#!/bin/bash\nls -la /home/rmstxrx")

# 2. Get relay token
token = prepare_relay()

# 3. Push script to host
curl -H "Authorization: Bearer $token" \
  -F "file=@/home/claude/task.sh" \
  "https://maestro.rmstxrx.dev/transfer/push?host=apollyon&remote_path=/tmp/maestro/inbox/20260329-143022-a3f1.sh"

# 4. Trigger execution
exec(host="apollyon", task_id="20260329-143022-a3f1")

# 5. Pull results (for completed tasks)
curl -H "Authorization: Bearer $token" \
  -o /home/claude/result.out \
  "https://maestro.rmstxrx.dev/transfer/pull?host=apollyon&remote_path=/tmp/maestro/outbox/20260329-143022-a3f1.out"

# 6. Read and reason about results locally
view("/home/claude/result.out")
```

For dispatched agents and services, the live interaction loop:

```
# Dispatch a Codex agent
dispatch(host="apollyon", agent="codex", ...)

# Check what the agent is doing right now (control-plane, ~50 lines)
observe(task_id="20260329-143022-a3f1")

# Send input if the agent needs it (control-plane, keystrokes)
steer(task_id="20260329-143022-a3f1", keys="y\n")

# Or abort
stop(task_id="20260329-143022-a3f1")
```

## Implementation Plan

### Phase 1: Staging Infrastructure
- Add `/tmp/maestro/inbox/` and `/tmp/maestro/outbox/` bootstrap to host
  init (alongside existing `~/.maestro/task_output/`)
- Add cleanup cron: `find /tmp/maestro -mmin +60 -delete`
- Ensure relay path validation allows `/tmp/maestro/` on all hosts

### Phase 2: Simplified Mux
- Replace `_build_wrapper` + `_build_script_wrapper` with single
  `_build_staged_wrapper(task_id, ssh_alias, cwd, sudo)` that generates
  the fixed exec template
- Remove all heredoc construction, `is_script` branching, and multi-layer
  escaping

### Phase 3: Tool Refactor
- Rename `run` → `exec`, remove `command` parameter, add `task_id`
- Remove `read`, `write`, `transfer`, `read_output` tools
- Update `service` to use staged script pattern
- Update ledger recording for new tool names

### Phase 4: Dispatch Adaptation
- `dispatch` already uses tmux via `create_task_window`. Adapt to use
  staged script pattern: write the agent CLI command as a script, push
  via relay (hub-local write since Maestro *is* on the hub), exec template.
- This eliminates the last remaining inline command construction.

### Phase 5: Cleanup
- Remove dead code from `mux.py`, `fleet.py`
- Update CLAUDE.md, AGENTS.md
- Update tool descriptions in connector config

## Consequences

### Positive
- **Zero escaping bugs.** Scripts are files. Files don't need shell escaping.
- **Zero blocking risk.** No data transits the MCP channel. All payload
  flows through HTTP relay with explicit pull semantics.
- **Full inspectability.** Every script sent and every result received lives
  on disk. SSH into any host, `cat /tmp/maestro/inbox/*.sh` to see exactly
  what was dispatched.
- **Replayability.** Re-run any task by re-executing its inbox script.
- **Tool surface reduction.** 13 → 9 tools. Simpler mental model.
- **Uniform interaction pattern.** Every task follows the same 5-step
  lifecycle. No branching on command length, script vs. single-line,
  read vs. run.

### Negative
- **Relay dependency.** If the HTTP relay is down, no data flows. Mitigated:
  relay runs in the same container as Maestro (single failure domain).

### Costs (Accurately Stated)

The overhead is smaller than a naive step-count suggests:

- **Script reuse.** Scripts are staged once and reused across a session.
  `ls -la`, `tail -50 /var/log/...`, `nvidia-smi` — these get pushed once
  on first use. Subsequent executions skip the generate+push steps entirely.
  Amortized cost: `exec` + `pull` + `view` (1 MCP tool call + 2 bash).
- **Relay token longevity.** `prepare_relay` issues a 1-hour token. One
  call covers an entire working session. Not a per-task cost.
- **Parity with auto-promote.** The current SSE client has
  `block_timeout_exec: 5`. Any `run` task exceeding 5 seconds already
  returns only `{task_id, status}`, requiring a follow-up `read_output`
  call. So the current cost for most tasks is already 2 MCP tool calls.
  Under ADR-0009, the equivalent is 1 MCP call (`exec`) + 2 container-local
  bash steps (`curl pull` + `view`) — comparable or cheaper since bash
  steps don't transit the cloudflared tunnel.
- **The 5-second window is the problem, not a feature.** The only scenario
  where the current model is "cheaper" is tasks that complete inline within
  5 seconds. But that window is precisely where blocking surprises occur:
  a command expected to take 2s takes 40s, freezing the UI. ADR-0009
  eliminates this failure mode entirely — `exec` is always non-blocking.

### Neutral
- **Local agent execution** is explicitly out of scope. Agents running
  locally on hosts (Claude Code, Codex, Gemini) use native filesystem
  access. Maestro is the interface for Claude in claude.ai — the strategist
  — not for local agents.
- **Tmux remains** as execution wrapper. It was never the problem; the
  input/output channels were.

## Appendix: Eliminated Complexity

The following code in `mux.py` is deleted or reduced to ~10 lines:

- `_build_wrapper()` (54 lines) — nested shlex.quote, SSH wrapping,
  tee piping, PIPESTATUS extraction, powershell branching
- `_build_script_wrapper()` (59 lines) — heredoc construction,
  `cat << '__MAESTRO_SCRIPT__'` pipe chains, remote temp file management,
  powershell SCP fallback

The following tools in `fleet.py` are deleted entirely:

- `read()` (27 lines) — SSH cat/head/tail with powershell branching
- `write()` (35 lines) — SSH tee/stdin piping with sudo/append/powershell
- `transfer()` (20 lines) — SCP wrapper with direction branching

Total lines eliminated: ~195 lines of high-complexity escaping code.
Total lines added: ~30 lines (staged wrapper builder + exec tool).

Net delta: **−165 lines**, with the removed lines being disproportionately
bug-prone compared to the codebase average.
