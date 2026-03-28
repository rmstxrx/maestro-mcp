# ADR-0004: Fork Cherry-Pick and Poll Hardening

**Status:** Proposed  
**Date:** 2026-03-19  
**Deciders:** (maintainer), Claude  
**Relates to:** ADR-0003 (reliability refactor), BUG-0001 (cross-host poll leakage)

## Context

`lirnut/maestro-mcp` forked our codebase on ~Mar 15 (from commit `66f0c4a`) and
diverged with ~50 commits in 4 days. A thorough review identified several ideas
worth adopting alongside one we deliberately reject (replacing ControlMaster with
asyncssh). Simultaneously, BUG-0001 demonstrated that the MCP Streamable HTTP
transport layer can misroute `poll()` responses under concurrent SSE sessions —
a bug we cannot fix from Maestro's side, but can architecturally mitigate.

This ADR combines both into a single coherent refactoring pass.

### What we're taking from the fork (adapted, not copied)

| Idea | Source | Our adaptation |
|------|--------|----------------|
| SSH config parsing for discovery | `hosts.py` _parse_ssh_config() | Read-only. We do NOT use parsed params for connections — ControlMaster handles that natively. Discovery only. |
| Per-host default agent preference | `RemoteCLI` enum on `HostConfig` | Direct adopt. Clean extension, no behavioral change. |
| Project-level hosts.yaml search | `_find_hosts_config()` priority chain | Adopt with minor simplification (drop CWD search — too implicit). |
| reconnect_host tool | `fleet.py` reconnect_host() | Rewrite for ControlMaster (teardown + warmup), not asyncssh pool. |
| Dynamic fleet management | `add_host()` | Adopt with mandatory user approval in tool description. |
| SSH host discovery tool | `list_ssh_hosts()` | Adapt as read-only, cross-referenced with hosts.yaml. |
| Agent-specific docs | AGENTS.md, GEMINI.md | Write our own versions. |

### What we're NOT taking

| Idea | Reason |
|------|--------|
| asyncssh connection pool | Breaks ProxyJump (Win-server-WSL), requires reimplementing SSH config in Python, `known_hosts=None` is a security regression. ControlMaster is architecturally superior for our fleet. |
| Password/key_passphrase in HostConfig | Plaintext credentials in hosts.yaml. Our model: SSH agent + config handles auth. |
| install_agent tool | Too coupled to specific CLI install procedures that change upstream. Manual install is fine for 3 hosts. |
| Persistent tmux sessions (6 tools) | Overlaps auto-promote. Tool count explosion (12→18 just for this). Revisit as a single `persistent_exec` tool later if needed. |
| OpenCode CLI integration | We don't use it. Clean architecture if we ever want it. |

### BUG-0001 hardening rationale

The root cause is **MCP SSE session multiplexing misrouting responses** under
concurrent tool calls. Evidence: `GET /mcp → 409 Conflict` in server logs;
task registry contains correct data but Claude.ai attributes the response to
the wrong tool call.

**We cannot fix this from Maestro's side.** The server returns correct data;
the corruption happens in the transport layer between Maestro and Claude.ai.

**The `GET /tasks/{task_id}/result` HTTP endpoint is architecturally immune.**
It uses `bash_tool` → `curl`, a separate HTTP request-response cycle with no
SSE multiplexing. No shared session means no response interleaving.

**Current state:** `_inject_poll_verification()` adds `_verify_host` metadata
to poll results — detection, not prevention. `poll(wait=N)` still blocks the
MCP tool call, occupying the SSE session and increasing the collision window.

**Proposed fix:** Make `poll(wait>0)` return an HTTP redirect payload instead
of blocking. The MCP `poll` tool becomes a lightweight status check + router;
actual result retrieval happens through the immune HTTP endpoint.

## Decision

Four phases, each independently committable and testable.

### Phase 1 — hosts.py expansion (~125 lines added)

Foundation for everything else. No new tools, no behavioral changes.

**Commit 1: `feat(hosts): add RemoteCLI enum, SSH config parsing, project-level config search`**

Files changed: `maestro/hosts.py`, `maestro/config.py`

1. **RemoteCLI enum** — `codex | gemini | claude` (no `opencode`). Added to
   `HostConfig` as `remote_cli: RemoteCLI = RemoteCLI.CODEX`. Loaded from
   `hosts.yaml` via `remote_cli:` key.

2. **`_parse_ssh_config(alias)`** — Parse `~/.ssh/config` for a given Host
   alias. Returns `{hostname, port, user, key_path}`. Used for display/
   discovery only, never for connection params. ControlMaster handles the
   actual resolution. Limitations documented: no Match, Include, or complex
   directives.

3. **`_list_ssh_config_hosts()`** — Enumerate all `Host` blocks in
   `~/.ssh/config`. Returns list of `{aliases, hostname, port, user}`.
   Cross-references with HOSTS to mark `in_fleet: true/false`.

4. **`_find_hosts_config()`** — Priority search for hosts.yaml:
   - `MAESTRO_HOSTS_PATH` env var (if set and exists)
   - `MAESTRO_PROJECT_DIR/.maestro/hosts.yaml` (if env var set and exists)
   - Fall through to global default (current behavior)

   We skip the fork's "CWD search" (looking in `Path.cwd() / .maestro/`)
   because it's too implicit — different CWDs at startup would silently
   load different fleet configs. Explicit env var or project dir only.

### Phase 2 — new fleet tools (~125 lines added)

Three new tools. Tool count: 12 → 15.

**Commit 2: `feat(fleet): add reconnect_host, list_ssh_hosts, add_host tools`**

Files changed: `maestro/tools/fleet.py`

1. **`reconnect_host(host: str)`** — Tears down the ControlMaster socket
   (`ssh -O exit <alias>`) then warms up a fresh connection (`ssh <alias>
   true`). Returns structured JSON with connection status. Uses existing
   `_teardown_connection()` and `_warmup_connection()` from transport.py.
   For local hosts, returns immediately with `"status": "local"`.

2. **`list_ssh_hosts()`** — Calls `_list_ssh_config_hosts()` from Phase 1.
   Returns JSON array with `in_fleet` flag. No parameters. Read-only
   discovery tool for fleet setup.

3. **`add_host(name, alias, description, remote_cli, is_local)`** — Writes
   a new entry to `hosts.yaml` and calls `init_hosts()` to hot-reload.

   **Critical safety constraint:** The tool description MUST include
   language like: "This modifies your fleet configuration file. The AI
   assistant must describe the proposed change and get explicit user
   approval before calling this tool." This is enforced by the MCP tool
   description, not by code — the LLM reads the description and should
   ask for confirmation. We do NOT include password or key_passphrase
   parameters (unlike the fork). Auth is handled by SSH config/agent.

   No `password` or `key_passphrase` parameters — credentials belong in
   `~/.ssh/config` and SSH agent, not in `hosts.yaml`.

### Phase 3 — poll() hardening (~40 lines changed)

Makes the immune path the default. No new tools.

**Commit 3: `fix(BUG-0001): poll(wait>0) redirects to HTTP endpoint`**

Files changed: `maestro/tools/fleet.py`, `TOOLS.md`

Current behavior:
```
poll(task_id, wait=120)  →  blocks MCP tool call for up to 120s
                         →  occupies SSE session the whole time
                         →  vulnerable to BUG-0001 response mixing
```

New behavior:
```
poll(task_id, wait=0)    →  immediate status check (unchanged)
                         →  returns task status JSON

poll(task_id, wait>0)    →  returns HTTP endpoint redirect:
                            {
                              "status": "use_http_endpoint",
                              "task_id": "...",
                              "endpoint": "/tasks/{task_id}/result",
                              "curl_pattern": "TOKEN=$(...); for i in $(seq 1 N); do ... done",
                              "hint": "Use bash_tool with curl loop for safe polling — immune to SSE mixup"
                            }
                         →  MCP tool returns instantly (no SSE session occupation)
                         →  agent uses bash_tool + curl (separate HTTP, no multiplexing)
```

The `poll` tool description is updated to explain why: "Long-wait polling via
MCP is vulnerable to transport-layer response misrouting (BUG-0001). For
wait>0, use the HTTP endpoint via bash_tool instead."

This is NOT a breaking change — `poll(wait=0)` (the default) is untouched.
The `wait>0` path was added in the Codex dispatch session and hasn't been
used in production yet (we've been using the curl pattern since the HTTP
endpoint shipped).

### Phase 4 — documentation

Non-code. Land last.

**Commit 4: `docs: AGENTS.md, GEMINI.md, ADR-0004, journal entry`**

Files added/changed:
- `AGENTS.md` — Development guide for AI coding agents working on the
  codebase. Build/test commands, code style, import order, type annotation
  conventions. Adapted from fork's version with our specific patterns.
- `GEMINI.md` — Getting started guide for Gemini CLI with Maestro. Core
  fleet workflows, tool reference, context budget tips.
- `docs/adr/0004-fork-cherry-pick.md` — This document.
- `docs/journal/2026-03-19-fork-analysis.md` — Session log.

## Consequences

### Tool inventory after this ADR

| Tool | Category | Status |
|------|----------|--------|
| exec | Fleet | Unchanged |
| script | Fleet | Unchanged |
| read | Fleet | Unchanged |
| write | Fleet | Unchanged |
| transfer | Fleet | Unchanged |
| status | Fleet | Unchanged |
| **reconnect_host** | **Fleet** | **New** |
| **list_ssh_hosts** | **Fleet** | **New** |
| **add_host** | **Fleet** | **New (requires approval)** |
| codex | Orchestra | Unchanged |
| gemini | Orchestra | Unchanged |
| claude | Orchestra | Unchanged |
| gemini_sessions | Orchestra | Unchanged |
| poll | Orchestra | **Modified (wait>0 redirects)** |
| read_output | Orchestra | Unchanged |
| prepare_relay | Relay | Unchanged |
| agent_status | Orchestra | Unchanged |

**17 tools total** (was 14 post-ADR-0003 with prepare_relay and agent_status).

### What this does NOT address

- The MCP transport mixup itself (FastMCP SDK / Claude.ai client bug)
- asyncssh as an alternative transport (explicitly deferred — ControlMaster
  is correct for our fleet topology)
- Persistent tmux sessions (revisit as single tool if needed)
- OpenCode CLI integration (not in our workflow)

### Risk assessment

- **Phase 1:** Zero risk — purely additive data model changes, no behavioral
  changes. Existing tests unaffected.
- **Phase 2:** Low risk — new tools only, don't modify existing tools.
  `add_host` has the highest surface area (writes to hosts.yaml + hot-reload)
  but is guarded by the approval convention.
- **Phase 3:** Medium risk — changes `poll(wait>0)` behavior. Mitigated by:
  `wait=0` default is untouched; the `wait>0` path is unused in production
  (we already use the curl pattern); agents that pass `wait>0` get a helpful
  redirect instead of a silent timeout.
- **Phase 4:** Zero risk — documentation only.

### Estimated effort

~350 lines added across 5 Python files + 3 markdown files. Each phase is
independently committable. Total implementation time: ~2-3 hours of focused
Codex/Claude Code work, or one session of manual implementation with review.
