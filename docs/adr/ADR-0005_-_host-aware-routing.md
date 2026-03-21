# ADR-0005: Host-Aware Agent Routing

**Status:** Proposed  
**Date:** 2026-03-19  
**Deciders:** rmstxrx, Claude  
**Relates to:** ADR-0004 (fork cherry-pick), BUG-0001 (cross-host poll leakage)

## Context

Maestro currently treats all clients identically: every command, regardless of
who's asking, is routed through Maestro's transport layer. This creates a
pathological pattern for **local agents** (Claude Code, Codex CLI, Gemini CLI)
running on the hub machine.

### The problem

When Claude Code runs on Apollyon (dispatched via `Maestro:claude`), it has
two ways to execute commands on Apollyon:

1. **Native Bash tool** — direct subprocess, zero overhead, full terminal
   capabilities, immediate.

2. **Maestro:exec(host="apollyon", ...)** — MCP stdio → Maestro → `is_local`
   check → subprocess → MCP stdio response. Three layers of indirection
   for the same subprocess call.

In practice, local agents almost always converge on option 2. After interacting
with Maestro's fleet tools for remote hosts, the agent develops a habit of
routing *everything* through Maestro — including commands targeting the very
machine it's sitting on.

This is not merely inefficient. It's architecturally wrong:

- **Unnecessary indirection** — the command takes the same path (subprocess)
  but with MCP serialization/deserialization overhead on both ends.
- **Reduced capability** — Maestro's `exec` doesn't support interactive
  terminals, streaming output, or signal forwarding. The agent's native
  Bash tool does.
- **Action laundering** — the agent routes a local command through an
  intermediary that adds no authority, no capability, and no safety. Like
  a lawyer sending a letter to their own office through the postal service.

The root cause: **agents don't know where they are.** Nothing in Maestro's
MCP instructions or tool responses tells a stdio agent "you are running on
apollyon." The agent sees named hosts and tools, with no sense of self-location.

### Current client classification

Maestro already classifies clients via `get_client_context()`:

| Client type | Detection | Example |
|---|---|---|
| `remote` | Has `CF-Ray` header (Cloudflare) | Claude.ai via tunnel |
| `lan` | Has `MAESTRO_LAN_ORIGINS` match | LAN browser/API client |
| `local` | HTTP but no CF-Ray, no LAN match | localhost HTTP client |

Missing: **`stdio`** — agents connected via MCP stdio transport (no HTTP
headers at all). This is how Claude Code, Codex CLI, and Gemini CLI connect.

## Decision

### 1. Add `stdio` client classification

In `maestro/client.py`, add a `stdio` client type. Detection: if there are
no HTTP headers (the request didn't come through HTTP at all), classify as
`stdio`. This is the simplest possible check — stdio transport means no
`Request` object, no headers, nothing to inspect.

The client profile for `stdio` should match or exceed `local`:

```python
STDIO_PROFILE = {
    "block_timeout_agent": 30,
    "block_timeout_exec": 60,
    "poll_cooldown": 2,
}
```

### 2. Dynamic instructions based on client type

`_build_instructions()` in `server.py` currently returns static text. Make
it dynamic based on the transport used.

For **stdio** clients (local agents on the hub):

```
You are running locally on {local_host_name} ({local_host_description}).

CRITICAL: Do NOT use Maestro exec/script/read/write to target {local_host_name}.
You have native tools (Bash, filesystem) that are faster and more capable.
Maestro will reject local-targeting commands from local agents.

Use Maestro ONLY for:
  - Remote fleet hosts: {comma-separated remote host names}
  - Agent dispatch (codex, gemini, claude) to any host
  - Fleet status, agent_status, transfer, prepare_relay
  - poll, read_output (task registry operations)

Fleet topology:
  {host_name}: {description} [REMOTE]
  {host_name}: {description} [LOCAL — use native tools]
```

For **HTTP** clients (Claude.ai, remote):

```
You are a remote client. Use Maestro tools for all fleet operations.
...existing instructions...
```

Implementation note: FastMCP's `instructions` field is set at server
construction time, not per-request. For stdio transport, we can set it
at startup since the hub identity is known. For HTTP, the existing
instructions remain. If FastMCP eventually supports per-session
instructions, we can refine further.

### 3. Block local-targeting fleet commands from stdio clients

In `maestro/tools/fleet.py`, add a guard at the top of `exec`, `script`,
`read`, and `write`:

```python
def _check_local_self_reference(host: str) -> str | None:
    """If a stdio client is targeting the local host, return an error.
    Returns None if the command should proceed."""
    ctx = get_client_context()
    if ctx.client_type != "stdio":
        return None
    cfg = _resolve_host(host)
    if not cfg.is_local:
        return None
    return json.dumps({
        "error": "local_self_reference",
        "host": host,
        "blocked": True,
        "message": (
            f"You are running on {host}. Use your native Bash/filesystem "
            f"tools for local commands — they are faster and more capable. "
            f"Maestro fleet tools are for remote hosts only."
        ),
    })
```

Each tool checks at entry:

```python
@mcp.tool()
async def exec(host: str, command: str, ...) -> str:
    if block := _check_local_self_reference(host):
        return block
    # ... existing logic
```

### 4. Tools NOT affected by the block

These tools remain available to stdio clients regardless of target host:

| Tool | Reason |
|---|---|
| `status` | Fleet-wide health check, no host parameter |
| `agent_status` | Reports CLI availability — coordination value |
| `codex`, `gemini`, `claude` | Agent dispatch — Maestro adds task registry, output capture, auto-promote. Native tools can't replicate this. |
| `poll`, `read_output` | Task registry operations |
| `transfer`, `prepare_relay` | File relay between hosts |
| `reconnect_host` | Connection management |
| `list_ssh_hosts`, `add_host` | Fleet discovery/management |

The distinction is clean: **fleet I/O tools** (exec, script, read, write)
get blocked for local targets from stdio clients. **Orchestration tools**
(everything else) remain available because they provide coordination value
that native tools cannot replicate.

### 5. stdio detection implementation

The challenge: FastMCP handles transport selection before our code runs.
For stdio transport, there is no HTTP request — the MCP messages arrive
via stdin/stdout. We need to detect this at startup and propagate it.

Approach: In `server.py`, when `--transport stdio` is passed, set a
module-level flag that `get_client_context()` can read:

```python
# server.py entry point
if args.transport == "stdio":
    from maestro.client import set_stdio_mode
    set_stdio_mode(local_host_name=_local_host_name())
```

In `client.py`:

```python
_STDIO_MODE = False
_STDIO_LOCAL_HOST: str | None = None

def set_stdio_mode(local_host_name: str | None = None):
    global _STDIO_MODE, _STDIO_LOCAL_HOST
    _STDIO_MODE = True
    _STDIO_LOCAL_HOST = local_host_name

def get_client_context() -> ClientContext:
    if _STDIO_MODE:
        return ClientContext(
            client_type="stdio",
            local_host=_STDIO_LOCAL_HOST,
            profile=STDIO_PROFILE,
        )
    # ... existing HTTP-based classification
```

## Consequences

### Behavioral changes

| Client | Target local host | Target remote host |
|---|---|---|
| Claude.ai (HTTP) | **Allowed** — only path | Allowed |
| stdio agent on hub | **Blocked** — use native tools | Allowed |

### What this enables

- Local agents naturally partition their work: native tools for local,
  Maestro for remote. No wasted round-trips.
- Clearer mental model for agents: "I am on apollyon, these are my
  neighbors, here's how I reach them."
- Reduced MCP traffic on stdio for local operations, which also reduces
  the serialization overhead on the host machine.

### What this does NOT do

- Force agents to use native tools — it blocks the Maestro path and
  provides an instructive error. Well-behaved agents will adapt. Poorly
  instructed agents will need their CLAUDE.md / AGENTS.md updated to
  reinforce the pattern.
- Affect HTTP clients in any way — Claude.ai continues to use Maestro
  for everything, as it must.
- Change how agent dispatch works — `Maestro:claude(host="apollyon", ...)`
  remains valid from stdio clients because the dispatch tools provide
  coordination value (task registry, output capture, auto-promote).

### Risk assessment

- **Low risk.** The block only affects 4 tools (exec, script, read, write)
  for one client type (stdio) when targeting one host (local). All other
  paths are untouched.
- **Graceful degradation.** If the detection is wrong (client misclassified),
  the error message clearly explains what happened and how to proceed.
- **Reversible.** The block is a single `if` check at tool entry. Removing
  it restores previous behavior instantly.

### Estimated effort

~80 lines across `client.py`, `fleet.py`, and `server.py`. One commit.
Could be done manually in 30 minutes or dispatched to Claude Code.
