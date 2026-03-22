# ADR-0006: Task Ledger, Dispatch Enforcement, and Relay TTL

**Status:** Proposed  
**Date:** 2026-03-22  
**Deciders:** rmstxrx, Claude  
**Relates to:** BUG-0001 (cross-host poll leakage), ADR-0005 (host-aware routing)

## Context

Three friction points have converged around the same gap — Maestro has no
authoritative, persistent record of dispatched work.

### 1. Polling is a lose-lose

When an agent dispatches a long-running task (Codex at `xhigh` reasoning,
Gemini Deep Think, a 10-minute build), the orchestrating session has two
options for monitoring:

- **Repeated `poll` calls** — each one is an MCP tool invocation that burns
  context tokens, clutters the chat, and can trigger BUG-0001 (MCP
  transport misrouting the response to the wrong task).
- **Blocking `bash_tool` curl loop** — the claude.ai UI has an implicit
  turn timeout. A curl loop that blocks for 10 minutes will be deemed
  failed by the UI, wasting both the wait time and the turn.

Neither option works. The conversation is held hostage during the wait,
and the result retrieval is unreliable.

The HTTP endpoint `GET /tasks/{task_id}/result` already exists and
returns 202 (running) or 200 (done) — bypassing MCP transport entirely.
But the ephemeral relay token (`prepare_relay`) expires after 5 minutes,
which is shorter than most non-trivial agent tasks. Background watchers
that outlive the TTL get 401s.

### 2. Task identity is fragile

`TASK_REGISTRY` is a runtime dict that doubles as both execution tracker
and historical record. Its problems:

- **No client attribution** — who dispatched the task? Was it the Claude.ai
  session, a local Claude Code agent, or a LAN client? Unknown.
- **Eviction destroys history** — when `_evict_stale_tasks()` runs, the
  task vanishes from memory and disk. There is no way to answer "what
  ran yesterday?" or "show me all Codex tasks this week."
- **Metadata is scattered** — return code is buried in `result_json`,
  the HTTP retrieval URL must be constructed manually, timing data
  requires parsing datetimes.
- **BUG-0001 mitigation is detect-only** — `_inject_poll_verification`
  adds `_verify_host` fields so the caller can detect misrouted results,
  but detection without a lookup table is just a fancier confusion. The
  caller sees "wrong host" and has no way to find the right result.

The underlying issue: there is no **ledger** — a single, queryable record
of every task Maestro has dispatched, its disposition, and where to find
its output.

### 3. Agents bypass the orchestra

Despite `exec`'s docstring saying "Do NOT use this to invoke agent CLIs,"
the orchestrating LLM sometimes dispatches agents via raw `exec` commands:

```
exec(host="apollyon", command="codex -q --model o4-mini ...")
```

This causes:
- **Wrong CLI arguments** — the LLM guesses at flags from fuzzy training
  data instead of using the tested command builder in `_orchestra_run_cli`.
- **No AGENT_SCOPE_PREFIX** — the subagent receives no scope constraints,
  no naming convention pointer, no debrief instruction.
- **No ledger/registry entry** — the task is invisible to `poll`, `tasks`,
  `read_output`. No tracking, no output file, no auto-promote.
- **No auto-promote** — the `exec` call blocks until timeout or returns
  a truncated result.

The pattern is analogous to filing a lawsuit by mailing it directly to
the judge's house instead of going through the court clerk. It might
work, but there's no docket entry, no case number, and no record.

## Decision

### 1. Task Ledger — persistent append-only log

Introduce `TaskLedger` alongside the existing `TaskRegistryStore`.
The registry remains the **runtime engine** (asyncio tasks, done events,
live references). The ledger becomes the **permanent record**.

#### Ledger record schema

| Field | Type | Source |
|---|---|---|
| `task_id` | str | Generated at dispatch (existing `secrets.token_hex(8)`) |
| `agent` | str | `codex` / `gemini` / `claude` / `exec` / `script` |
| `host` | str | Target host name |
| `prompt` | str | First 200 chars of the dispatched prompt/command |
| `status` | str | `running` → `done` / `failed` / `timeout` / `orphaned` |
| `client_class` | str | `remote` / `local` / `lan` / `stdio` |
| `dispatched_at` | ISO datetime | When Maestro received the dispatch request |
| `completed_at` | ISO datetime | When the task reached terminal status |
| `return_code` | int \| null | Exit code, extracted from result at completion |
| `output_file` | str \| null | Absolute path to the agent output file on disk |
| `result_url` | str | Full HTTPS URL: `{issuer_url}/tasks/{task_id}/result` |

#### Storage

JSON file at `~/.maestro/task_ledger.json` (configurable via
`MAESTRO_TASK_LEDGER_PATH` env var). Same atomic write-to-tmp-and-replace
pattern as `OAuthStateStore`.

#### Lifecycle

- **Create:** Entry written when `_auto_promote` registers a task, or
  when any dispatch tool (`codex`, `gemini`, `claude`) begins execution.
  Status = `running`.
- **Update:** When status changes to `done`/`failed`/`timeout`, the
  ledger entry is updated with `completed_at` and `return_code`.
- **Eviction:** `_evict_stale_tasks()` cleans `TASK_REGISTRY` as before,
  but the ledger entry is **never evicted** by the runtime evictor.
- **Retention:** Ledger entries older than 30 days may be pruned by a
  separate `_prune_ledger()` call (or manually). This is housekeeping,
  not eviction.

#### Relationship to TASK_REGISTRY

```
  Dispatch request
       │
       ▼
  ┌──────────────┐    ┌──────────────┐
  │ TASK_REGISTRY │    │  TaskLedger  │
  │  (runtime)    │    │ (persistent) │
  │               │    │              │
  │ asyncio.Task  │    │ task_id      │
  │ _done_event   │    │ agent        │
  │ result_json   │    │ host         │
  │ output_file   │    │ prompt       │
  │               │    │ status       │
  │  evicted      │    │ client_class │
  │  after N hrs  │    │ dispatched_at│
  └──────────────┘    │ completed_at │
                      │ return_code  │
                      │ output_file  │
                      │ result_url   │
                      │              │
                      │  pruned      │
                      │  after 30d   │
                      └──────────────┘
```

### 2. New tool: `tasks`

Query the ledger as a table. Returns recent entries with optional filters.

```python
@mcp.tool()
async def tasks(
    status: str | None = None,     # filter: "running", "done", "failed"
    agent: str | None = None,      # filter: "codex", "gemini", "claude"
    host: str | None = None,       # filter: host name
    last: int = 10,                # number of recent entries
) -> str:
    """List recent tasks from the task ledger. Filterable by status, agent, host."""
```

Returns a compact table with: `task_id`, `agent`, `host`, `status`,
`dispatched_at` (relative, e.g. "12m ago"), `return_code`, `output_file`.

This answers: "what's running?", "what finished?", "where are the results
for the Codex task from 20 minutes ago?"

### 3. `poll` becomes status-only

`poll(task_id)` returns the ledger row for a single task — metadata only.
It **never** returns the result payload through MCP.

```python
@mcp.tool()
async def poll(task_id: str) -> str:
    """Check task status. Returns metadata only — retrieve full results
    via the HTTP endpoint (result_url) or read_output(output_file)."""
```

Response for a running task:
```json
{
    "task_id": "abc123",
    "agent": "codex",
    "host": "apollyon",
    "status": "running",
    "dispatched_at": "2026-03-22T14:30:00Z",
    "elapsed_seconds": 142.3,
    "result_url": "https://maestro.rmstxrx.dev/tasks/abc123/result"
}
```

Response for a completed task:
```json
{
    "task_id": "abc123",
    "agent": "codex",
    "host": "apollyon",
    "status": "done",
    "dispatched_at": "2026-03-22T14:30:00Z",
    "completed_at": "2026-03-22T14:35:12Z",
    "return_code": 0,
    "output_file": "/home/rmstxrx/.agent-orchestra/outputs/codex_20260322_143000_abc123.txt",
    "result_url": "https://maestro.rmstxrx.dev/tasks/abc123/result"
}
```

The `wait` parameter is removed entirely. The orchestrator is expected to
use the background watcher pattern (see Consequences) rather than blocking.

### 4. Dispatch guard on `exec` / `script`

Add a detection layer that rejects agent CLI invocations through `exec`
and `script`, redirecting to the proper dispatch tools.

```python
_AGENT_CLI_PATTERNS = re.compile(
    r'\b(codex|gemini|claude)\b.*(-[pq]|--prompt|--model|--message)',
    re.IGNORECASE,
)

def _check_agent_dispatch_bypass(command: str) -> str | None:
    """If command looks like a direct agent CLI invocation, block it
    and redirect to the proper dispatch tool."""
    match = _AGENT_CLI_PATTERNS.search(command)
    if not match:
        return None
    agent = match.group(1).lower()
    return json.dumps({
        "error": "dispatch_bypass_blocked",
        "blocked": True,
        "detected_agent": agent,
        "message": (
            f"Direct '{agent}' CLI invocation via exec/script is blocked. "
            f"Use the Maestro '{agent}' dispatch tool instead — it ensures "
            f"correct CLI arguments, applies AGENT_SCOPE_PREFIX, registers "
            f"the task in the ledger, and enables auto-promote + polling."
        ),
    })
```

Applied at entry of `exec` and `script`, after the existing
`_check_local_self_reference` guard.

#### Edge cases

- **Legitimate non-dispatch uses** — e.g., `exec(command="codex --version")`
  or `exec(command="which codex")`. The regex requires both the agent name
  AND a prompt/model flag, so version checks and path lookups pass through.
- **Obfuscation** — an LLM could theoretically construct the command via
  variable expansion to dodge the regex. This is a guardrail, not a
  security boundary. If the LLM actively works around it, we have a
  deeper instruction-following problem.

### 5. Relay TTL: 300s → 3600s

`prepare_relay` registers ephemeral tokens with a 5-minute TTL. This is
too short for the background watcher pattern — a Codex task at `xhigh`
reasoning regularly takes 10–15 minutes.

Change: hardcode TTL to 3600s (1 hour). No parameter needed — there's no
use case for a shorter-lived token, and adding a parameter creates an
opportunity for the LLM to guess wrong.

```python
async def prepare_relay() -> str:
    """Prepare the file relay for use. Call once before using push/pull
    endpoints or task result watchers. Token valid for 1 hour."""
    import secrets as _s
    from maestro.relay import register_ephemeral_token as _reg
    v = _s.token_urlsafe(32)
    _reg(v, ttl=3600)
    return json.dumps({"value": v, "ttl_seconds": 3600})
```

## Consequences

### The background watcher pattern

With these changes, the recommended workflow for auto-promoted tasks
becomes:

```
1. Dispatch tool returns {"auto_promoted": true, "task_id": "XYZ", ...}
2. Call prepare_relay → get $KEY (valid 1 hour)
3. bash_tool (returns immediately):
     ( for i in $(seq 1 40); do
         code=$(curl -s -o /tmp/task_XYZ.json -w '%{http_code}' \
           -H "Authorization: Bearer $KEY" \
           "https://maestro.rmstxrx.dev/tasks/XYZ/result")
         [ "$code" = "200" ] && break
         sleep 15
       done ) &
     echo "watcher launched"
4. Conversation continues — both parties free.
5. On demand: cat /tmp/task_XYZ.json (or: read_output <output_file>)
```

The HTTP endpoint does the waiting (returns 202 until done), the
background curl does the blocking (invisible to the chat), and the
conversation stays unblocked.

### What changes for each persona

| Persona | Before | After |
|---|---|---|
| **Claude.ai (orchestrator)** | Repeated `poll` calls or blocking curl loops | Dispatch → background watcher → check on demand |
| **rmstxrx (user)** | "check on that task" → 5 rounds of poll | `tasks` tool → instant table of all work |
| **Subagents** | Could be dispatched via `exec` with wrong args | Forced through dispatch tools with full scope + tracking |
| **Ledger** | Did not exist | Permanent record of all dispatched work |

### What this does NOT do

- **Change the HTTP `/tasks/{id}/result` endpoint.** It already works
  correctly (202/200). No server-side polling changes needed.
- **Add long-poll to the HTTP endpoint.** The background watcher pattern
  with `sleep 15` is sufficient and avoids the temptation for the LLM
  to issue a single blocking call with a large timeout.
- **Persist result payloads in the ledger.** The ledger stores metadata
  only. Full results remain in `output_file` on disk and retrievable via
  the HTTP endpoint. This keeps the ledger lightweight.

### Risk assessment

- **Low risk** — `TaskLedger` is additive (new file, new class). It does
  not modify `TASK_REGISTRY` behavior.
- **`poll` simplification** removes the `wait` parameter and the
  `_inject_poll_verification` path. This is a behavioral change but
  strictly a simplification — callers that used `wait>0` already got
  redirected to HTTP.
- **Dispatch guard** is a regex heuristic, not a parser. False positives
  are possible but unlikely given the pattern requires both an agent name
  and a prompt/model flag. False negatives (obfuscation) are accepted —
  it's a guardrail, not a sandbox.
- **Relay TTL increase** from 5 min to 1 hour expands the window in
  which a leaked token is valid. Acceptable because: tokens are
  single-use-ish (scoped to the session), the transfer relay is
  path-restricted (`MAESTRO_TRANSFER_ALLOWED_DIRS`), and the daily
  HMAC fallback already has a 24-hour window.

### Estimated effort

~200–250 lines of new/modified code across:
- `maestro/tools/orchestra.py` — `TaskLedger` class (~80 lines)
- `maestro/tools/fleet.py` — `tasks` tool, `poll` rewrite, dispatch
  guard, `prepare_relay` TTL (~100 lines)
- `maestro/config.py` — `MAESTRO_TASK_LEDGER_PATH` env var (~5 lines)
- `server.py` — wire `TaskLedger` into `configure_orchestra` (~10 lines)

One feature branch, implementable in a single session or dispatchable
to Codex/Claude Code.
