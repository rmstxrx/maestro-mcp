# ADR-0003: Reliability and Ergonomics Refactor

**Status:** Proposed
**Date:** 2026-03-12
**Deciders:** (maintainer), Claude

## Context

After three weeks of daily production use (Feb 22 – Mar 12), six friction points have surfaced that collectively degrade the Maestro experience. Some cause lost work (agent timeouts), some cause wasted context tokens (agents misusing exec for dispatch), and some create unnecessary manual intervention (transfer relay auth). None require architectural changes — the core design (FastMCP, SSH ControlMaster, auto-promote, OAuthStateStore) is sound. These are implementation-level fixes.

### Friction inventory

**F1 — Opaque error surface.** Every failure mode — SSH timeout, tunnel drop, MCP serialization error, auth rejection — collapses into the same generic `{"error": "Error occurred during tool execution"}`. This makes diagnosis a guessing game. The transport layer (`transport.py`) catches exceptions but discards context before returning.

**F2 — Task registry not persistent.** The `TASK_REGISTRY` dict lives in memory. If Maestro restarts mid-task, the registry is lost. Output files survive on disk (`~/.agent-orchestra/outputs/`), but the tracking metadata (task_id → status mapping) vanishes. The HTTP polling endpoint (`/tasks/{task_id}/result`) returns 404 for orphaned tasks.

**F3 — Transfer relay auth via shared secret in userPreferences.** The HMAC master secret is embedded in the user's `userPreferences` block, meaning it's injected into every conversation's system prompt — even conversations that never use the relay. This is excessive exposure. The daily-rotating HMAC derivation is sound; the distribution mechanism is not.

**F4 — No working-directory enforcement on agent dispatch.** Agents dispatched to Win-server (or any host) can create files anywhere — WSL home dirs, wrong drives, unrelated repos. The `cwd` parameter is passed through but never validated against a per-host policy. This caused scope creep incidents where agents pushed commits to forks of unrelated projects.

**F5 — Agent CLI timeouts hardcoded at 600s.** All three agent CLIs (Codex, Gemini, Claude Code) share a flat 600s timeout in `config.py`. Codex xhigh tasks routinely need 1500–1800s. Claude Code with complex prompts needs 900–1200s. Tasks that are 80% complete get SIGTERM'd, wasting the entire run and the tokens that dispatched them.

**F6 — Tool descriptions too terse; agents misuse exec for dispatch.** The `exec` tool description is `"Run a command on a host."` — no guidance on when *not* to use it. The dispatch tools (`codex`, `claude`, `gemini`) don't explain their value over raw exec (output capture, task registry, flag construction, auto-promote). Result: agents try to invoke `codex exec --dangerously-bypass...` via `exec()`, get quoting wrong, miss flags, lose output.

## Decision

### F1 — Structured error responses

Replace generic catch-all errors with categorized, informative responses.

In `transport.py` and `fleet.py`, catch specific exception types and return structured JSON:

```json
{
  "error": "ssh_timeout",
  "host": "win-server",
  "detail": "Command timed out after 300s",
  "command_preview": "python train.py --epochs 10..."
}
```

Error categories: `ssh_timeout`, `ssh_connection_failed`, `auth_failure`, `command_error` (nonzero exit), `transport_error` (tunnel/MCP), `validation_error` (bad params). Preserve the full stderr in the response for `command_error`.

### F2 — Persistent task registry

Apply the same pattern as `OAuthStateStore`: atomic JSON persistence to `~/.maestro/task_registry.json`.

- Save on every state transition (registered → running → done/failed).
- Load on startup; mark any task with status `running` as `orphaned` (the asyncio task handle is gone, but the output file may exist on disk).
- The HTTP endpoint `/tasks/{task_id}/result` should return `orphaned` tasks with a pointer to their output file path, rather than 404.
- Eviction still runs on the same schedule — persistence doesn't mean eternal retention.

### F3 — MCP-issued ephemeral transfer tokens

Add a new MCP tool: `get_transfer_token()`.

- Returns a short-lived bearer token (5-minute TTL, tied to the authenticated MCP session).
- The relay endpoints (`/transfer/push`, `/transfer/pull`, `/tasks/{task_id}/result`) accept this ephemeral token alongside the existing daily HMAC.
- The HMAC secret can then be removed from `userPreferences`. The flow becomes: Claude calls `get_transfer_token()` via MCP (authenticated) → uses the token in `curl` via `bash_tool` (zero context cost for file bytes).
- Keep the daily HMAC as a fallback/backward-compat mechanism, but it's no longer the primary auth path.

### F4 — Per-host allowed directories for dispatch

Extend `hosts.yaml` with an optional `allowed_dirs` field:

```yaml
hosts:
  win-server:
    alias: ssh-win-server
    shell: powershell
    allowed_dirs:
      - "C:\\Users\\user\\Development"
  gpu-server:
    alias: ssh-gpu-server
    allowed_dirs:
      - "/home/user/Development"
```

The dispatch tools (`codex`, `claude`, `gemini`) validate `working_dir` against the host's `allowed_dirs` before invoking the CLI. If unset, no validation (backward compatible). The `exec` and `script` tools do NOT enforce this — they're intentionally general-purpose.

### F5 — Configurable agent timeouts

Replace the hardcoded 600s values in `config.py` with env-configurable defaults:

```python
codex_timeout=int(os.environ.get("MAESTRO_CODEX_TIMEOUT", "1800")),
gemini_timeout=int(os.environ.get("MAESTRO_GEMINI_TIMEOUT", "900")),
claude_timeout=int(os.environ.get("MAESTRO_CLAUDE_TIMEOUT", "1200")),
```

Additionally, expose `timeout` as an optional parameter on each dispatch tool, so the caller can override per-task:

```python
async def codex(host, prompt, working_dir=..., timeout: int = 0, ...) -> str:
    effective_timeout = timeout if timeout > 0 else config.codex_timeout
```

### F6 — Richer tool descriptions

Update tool descriptions to guide correct usage:

**exec:** `"Run a shell command on a host. Do NOT use this to invoke agent CLIs (claude, codex, gemini) — use the dedicated dispatch tools instead, which handle output capture, task tracking, and proper CLI flags."`

**codex:** `"Dispatch a coding task to Codex CLI on a host. Handles flag construction, output capture to disk, task registry, and auto-promote to background. Returns a task_id — use poll() to get results. Prefer this over exec() for any Codex work."`

**claude:** `"Dispatch a coding task to Claude Code CLI on a host. Handles flag construction, output capture, task registry, and auto-promote. Returns a task_id — use poll() for results. Prefer this over exec() for any Claude Code work."`

**gemini:** `"Dispatch an analysis or research task to Gemini CLI on a host. Exploits Gemini's 1M-token context for deep codebase analysis and web-grounded research. Returns a task_id — use poll() for results. Prefer this over exec() for any Gemini work."`

## Consequences

### Positive
- Lost work from premature timeouts is eliminated (F5).
- Agent misuse of exec drops significantly with explicit guidance (F6).
- Maestro restarts no longer orphan task metadata (F2).
- Transfer relay works without a shared secret in every conversation (F3).
- Debugging becomes tractable with categorized errors (F1).
- Agent scope creep on Win-server is prevented at the tool level (F4).

### Negative
- Task registry persistence adds ~1 JSON write per state transition — negligible I/O but another file to manage.
- Ephemeral token mechanism adds one MCP round-trip per transfer session.
- `allowed_dirs` validation could be overly restrictive if not configured carefully; default is permissive (no validation) for backward compat.

### Neutral
- No changes to the OAuth flow, SSH transport, or MCP protocol surface.
- All fixes are additive or replacement — no tool removals or signature changes.
