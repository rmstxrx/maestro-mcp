# 2026-03-19 — Fork Analysis, Cherry-Pick, SSH Consolidation, Host Awareness

## Session scope

Four interleaved workstreams in one long session.

## 1. Fork analysis (lirnut/maestro-mcp)

Silent fork discovered. 50 commits ahead of upstream since Mar 15.

**Major architectural divergence:** replaced CLI SSH + ControlMaster with
asyncssh pure-Python connection pool. Decision: NOT adopting. ControlMaster
natively handles ProxyJump (Win-server-WSL), known_hosts verification, and the
full ~/.ssh/config directive set. asyncssh would require reimplementing SSH
config parsing in Python (their version is incomplete — no Match, Include,
ProxyJump). Their `known_hosts=None` is a security regression.

**Cherry-picks adopted (ADR-0004):**
- RemoteCLI enum on HostConfig (per-host default agent)
- _parse_ssh_config / _list_ssh_config_hosts (read-only discovery)
- _find_hosts_config (project-level hosts.yaml priority search)
- reconnect_host tool (ControlMaster teardown + warmup)
- list_ssh_hosts tool (SSH config enumeration)
- add_host tool (with mandatory user approval)
- AGENTS.md, GEMINI.md documentation patterns

**Cherry-picks rejected:** asyncssh pool, password/key_passphrase in
HostConfig, install_agent, persistent tmux sessions (6 tools), OpenCode CLI.

**Implementation:** Dispatched to Claude Code on GPU-server. All 4 phases
committed, 54/54 tests pass. Commits: 734f183, 6f4279e, 96854ba, 2deeff6.

## 2. BUG-0001 hardening (Phase 3 of ADR-0004)

poll(wait>0) changed from blocking the MCP tool call (occupying SSE session,
vulnerable to transport mixup) to returning an HTTP endpoint redirect payload.
The agent then uses bash_tool + curl — a separate HTTP cycle immune to SSE
multiplexing issues. poll(wait=0) unchanged.

## 3. SSH config consolidation (all 3 machines)

Root problem: every SSH alias (win-server.home, mcp-win-server, raw IP) generated
separate known_hosts entries. Duplicated config blocks between "interactive"
and "mcp-" aliases for the same hosts.

**Fix applied:** HostKeyAlias directive + multi-alias Host lines.

- `Host win-server win-server.home mcp-win-server` on one line — all aliases share one block
- `HostKeyAlias win-server.home` — one known_hosts entry regardless of alias used
- `Host mcp-*` wildcard for ControlMaster settings (additive merge)
- `Host *` for shared defaults (key, IdentitiesOnly, ServerAliveInterval)
- `HashKnownHosts no` — plaintext for manageability

Results:
- GPU-server: 21 → 4 known_hosts entries, 2 config blocks eliminated
- Mac-laptop: 42 → 2 known_hosts entries, 6 config blocks eliminated
- Win-server: 21 → ~2 entries (pending verification), simplified config

NVIDIA Sync Include preserved on both Mac-laptop and Win-server (tool-managed).
Backups created on all machines before changes.

## 4. Host-aware agent routing (ADR-0005)

Design for a new capability: Maestro tells stdio agents where they are,
and blocks fleet I/O tools (exec, script, read, write) when a local agent
targets its own host.

Key insight: the agent doesn't know it's *on* gpu-server. It sees a fleet
of named hosts and routes everything through Maestro — even commands
targeting itself. This is action laundering: routing local commands through
an intermediary that adds no authority.

ADR-0005 adds:
- `stdio` client classification (no HTTP headers → stdio)
- Dynamic instructions telling stdio agents their identity
- `_check_local_self_reference()` guard on fleet I/O tools
- Instructive error messages steering agents to native tools
- Orchestra tools (dispatch, poll, status) remain unblocked

## Pending

- Win-server known_hosts rebuild (task 151b53c37c0b9181 — still running)
- ADR-0005 implementation (proposed, not yet dispatched)
- Maestro restart needed for ADR-0004 tool changes to take effect
