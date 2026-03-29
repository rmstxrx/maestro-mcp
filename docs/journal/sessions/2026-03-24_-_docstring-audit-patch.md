# Maestro Documentation Patch — 2026-03-24

Source audit of fleet.py (653 lines), orchestra.py (811 lines), config.py, hosts.py, relay.py, transport.py, local.py, client.py, server.py.

This document contains every proposed change. Two sections:
1. **MCP Tool Docstrings** — the strings LLM callers see in the tool manifest
2. **CLAUDE.md** — the full replacement for agent-facing project documentation

---

## 1. MCP Tool Docstrings (fleet.py)

Each entry shows the function signature, the **current** docstring, and the **proposed** replacement. Only tools with substantive changes are listed — tools whose docstrings are already accurate are marked KEEP.

---

### `exec`
```python
async def exec(host: str, command: str, cwd: str | None = None, sudo: bool = False) -> str:
```
**Current:**
```
Run a shell command on a host. Do NOT use this to invoke agent CLIs (claude, codex, gemini) — use the dedicated dispatch tools instead.
```
**Proposed:**
```
Run a shell command on a host. Returns JSON with output.

Guards: rejects raw agent CLI invocations (use codex/claude/gemini tools instead). In stdio mode, rejects commands targeting the local host (use native Bash).
Auto-promotes to background if execution exceeds the client's block_timeout_exec (5s remote, 60s local). Check for "auto_promoted" in response.
Best for: grep, head, ls, git status, nvidia-smi, systemctl. Context cost = stdout size.
```

### `script`
```python
async def script(host: str, script: str, cwd: str | None = None, sudo: bool = False) -> str:
```
**Current:**
```
Run a multi-line script on a host. Do NOT use this to invoke agent CLIs — use dedicated dispatch tools.
```
**Proposed:**
```
Run a multi-line script on a host (piped via bash -s or PowerShell). Same guards and auto-promote as exec.

Use for multi-step operations with conditionals or loops. Bash scripts get set -euo pipefail prepended automatically.
```

### `read`
**KEEP** — current docstring is accurate and concise.

### `write`
```python
async def write(host: str, path: str, content: str, append: bool = False, sudo: bool = False) -> str:
```
**Current:**
```
Write content to a file on a host.
```
**Proposed:**
```
Write content to a file on a host. Creates parent directories automatically.

Content transits MCP (context-expensive for large payloads). For files >1KB that don't need inline reasoning, prefer prepare_relay + curl push instead.
```

### `transfer`
```python
async def transfer(host: str, direction: str, local_path: str, remote_path: str) -> str:
```
**Current:**
```
Transfer a file to/from a host via SCP. direction: "upload" or "download". For large files, prefer prepare_relay + curl push/pull (zero context cost).
```
**KEEP** — accurate.

### `status`
**KEEP** — accurate.

### `reconnect_host`
**KEEP** — accurate.

### `list_ssh_hosts`
**KEEP** — accurate.

### `add_host`
**KEEP** — accurate.

### `agent_status`
```python
async def agent_status(host: str = "") -> str:
```
**Current:**
```
Check Codex/Gemini CLI availability on a host.
```
**Proposed:**
```
Check Codex/Gemini/Claude Code CLI availability on a host. Also lists recent orchestra output files.
```
**NOTE:** The code only actually checks codex and gemini (`codex --version`, `gemini --version`). Claude Code is NOT checked. Two options:
  - (a) Fix the code to also run `claude --version` and update the docstring as proposed.
  - (b) Keep docstring as-is (Codex/Gemini only) and file an issue for the missing check.
  **Recommendation: (a)** — trivial code change alongside this doc pass.

### `codex`
```python
async def codex(host: str, prompt: str, working_dir: str, model: str = "", reasoning_effort: str = "xhigh", timeout: int = 0) -> str:
```
**Current:**
```
Dispatch a coding task to Codex CLI. Handles flags, output capture, task registry, auto-promote. Returns task_id — use poll() for results. Prefer over exec().
```
**Proposed:**
```
Dispatch a coding task to Codex CLI. Requires explicit working_dir (validated against host's allowed_dirs).

Handles: scope prefix injection, CLI flag construction, output capture to disk, task ledger recording, auto-promote to background. Default timeout: 1800s. Returns inline result or {auto_promoted: true, task_id} — use poll() for status, read_output() for full results.
```

### `claude`
```python
async def claude(host: str, prompt: str, working_dir: str, allowed_tools: str = "...", timeout: int = 0) -> str:
```
**Current:**
```
Dispatch a coding task to Claude Code CLI. Handles flags, output capture, task registry, auto-promote. Returns task_id — use poll() for results. Prefer over exec().
```
**Proposed:**
```
Dispatch a coding task to Claude Code CLI. Requires explicit working_dir (validated against host's allowed_dirs).

Handles: scope prefix injection, --permission-mode bypassPermissions, allowed_tools whitelist, output capture, task ledger, auto-promote. Default timeout: 1200s. Returns inline result or {auto_promoted: true, task_id} — use poll() for status, read_output() for full results.
```

### `gemini`
```python
async def gemini(host: str, prompt: str, working_dir: str, context_files: list[str] | None = None, model: str = "", approval_mode: str = "plan", resume: str = "", timeout: int = 0) -> str:
```
**Current:**
```
Dispatch an analysis/research task to Gemini CLI. Exploits 1M-token context. Returns task_id — use poll() for results. Prefer over exec().

approval_mode: "plan" (read-only), "yolo" (auto-approve all), "auto_edit" (auto-approve edits), "default" (prompt).
resume: Session index (e.g. "1") or "latest" to continue a previous chat.
WARNING: Resuming a session re-sends the entire history, costing tokens for all previous turns.
```
**KEEP** — this is already the best docstring in the codebase. Comprehensive and accurate.

### `poll`
```python
async def poll(task_id: str) -> str:
```
**Current:**
```
Check task status. Returns metadata only — retrieve full results via result_url or read_output(output_file).
```
**Proposed:**
```
Check task status in the persistent ledger. Returns metadata only: task_id, agent, host, status, timestamps, return_code, output_file, result_url.

Does NOT return result payloads. For full output: use read_output(output_file) for targeted line ranges, or curl the result_url (from prepare_relay) for zero-context retrieval.
```

### `tasks`
```python
async def tasks(status: str | None = None, agent: str | None = None, host: str | None = None, last: int = 10) -> str:
```
**Current:**
```
List recent tasks from the task ledger.
```
**Proposed:**
```
List recent tasks from the persistent ledger. Filters: status (running|done|failed|timeout|orphaned), agent (codex|claude|gemini|exec|script), host. Returns up to `last` entries sorted most-recent-first with relative timestamps.

Survives Maestro restarts. Tasks older than 30 days are auto-pruned.
```

### `read_output`
```python
async def read_output(file_path: str, start_line: int = 0, max_lines: int = 200) -> str:
```
**Current:**
```
Read full or partial output from a previous agent run.
```
**Proposed:**
```
Read full or partial output from a previous agent run. Restricted to files in the orchestra output directory.

Use start_line and max_lines for windowed reads to control context cost. Returns total_lines and has_more for pagination.
```

### `gemini_sessions`
**KEEP** — accurate.

### `prepare_relay`
```python
async def prepare_relay() -> str:
```
**Current:**
```
Prepare the file relay for use. Call once before using push/pull endpoints. Result is valid for 5 minutes.
```
**Proposed:**
```
Get an ephemeral bearer token for the HTTP transfer relay and task result endpoints. Valid for 1 hour. Use with: curl -H "Authorization: Bearer <token>" on /transfer/push, /transfer/pull, /tasks/{id}/result.
```

---

## 2. CLAUDE.md — Full Replacement

The current CLAUDE.md is good but has some stale sections (pre-ADR-0006 in the Key Patterns, missing `tasks` tool from architecture overview). Below is the proposed full replacement.

```markdown
# Maestro MCP — Developer Guide

Maestro is a multi-host machine fleet orchestration layer and AI agent orchestra, exposed via the Model Context Protocol (MCP). It turns a collection of SSH-accessible machines into a unified workspace.

## Architecture

Maestro is a modular Python package with a slim entry point:

- **Entry Point (`server.py`):** Configures FastMCP, sets up OAuth, wires modules, and starts the server (stdio or streamable-http).
- **Core Package (`maestro/`):**
    - **`tools/fleet.py`:** Fleet operations (`exec`, `script`, `read`, `write`, `transfer`, `status`), agent dispatch (`codex`, `gemini`, `claude`), task management (`tasks`, `poll`, `read_output`), relay (`prepare_relay`), and discovery tools (`list_ssh_hosts`, `add_host`, `agent_status`, `reconnect_host`, `gemini_sessions`).
    - **`tools/orchestra.py`:** Task registry, task ledger, auto-promote logic, agent output management, CLI runner helpers, scope prefix, and eviction loop.
    - **`hosts.py`:** Fleet topology management and `hosts.yaml` parsing. Supports Bash and PowerShell. Per-host `allowed_dirs` enforcement.
    - **`transport.py`:** Persistent SSH ControlMaster lifecycle (warmup, teardown, transient failure retries with exponential backoff).
    - **`local.py`:** Zero-overhead execution for the hub machine (`is_local: true`).
    - **`relay.py`:** HTTP endpoints for file transfers (`/transfer/push`, `/transfer/pull`) and task result retrieval (`/tasks/{id}/result`), bypassing the LLM context window.
    - **`client.py`:** Client classification (remote/local/lan/stdio) and per-client execution profiles controlling block timeouts and poll cooldowns.
    - **`oauth_state.py`:** Atomic JSON persistence for OAuth clients and tokens (survives restarts).
    - **`config.py`:** Environment-based configuration (`MaestroConfig`).

## Key Patterns

### 1. Auto-Promote (block_timeout)
Execution tools use `_auto_promote()` to handle long-running tasks:
- **Inline:** Try to finish within `block_timeout` (client-dependent: 30s local, 0s remote).
- **Background:** If timeout exceeds, tasks are shielded and moved to `TASK_REGISTRY`.
- **Monitoring:** Returns a `task_id`. Use `poll(task_id)` for status metadata. Use the HTTP endpoint or `read_output` for full results — `poll` never returns result payloads.

Client profiles (from `client.py`):
- **remote** (Claude.ai via Cloudflare): `block_timeout_agent=0` (always dispatch), `block_timeout_exec=5`
- **local** (localhost): `block_timeout_agent=30`, `block_timeout_exec=60`
- **lan** (198.51.100.*): `block_timeout_agent=10`, `block_timeout_exec=20`
- **stdio** (Claude Code): `block_timeout_agent=30`, `block_timeout_exec=60`

### 2. Task Ledger
Every dispatched task is recorded in a persistent, append-only ledger (`~/.maestro/task_ledger.json`). The ledger tracks: `task_id`, `agent`, `host`, `prompt`, `status`, `client_class`, `dispatched_at`, `completed_at`, `return_code`, `output_file`, and `result_url`. The ledger survives both task eviction and Maestro restarts (orphaned tasks are marked accordingly). Query it with the `tasks` tool. Auto-prunes entries older than 30 days.

### 3. Background Watcher Pattern
For auto-promoted tasks, the recommended monitoring workflow avoids blocking the conversation:

```
1. Dispatch tool returns {"auto_promoted": true, "task_id": "XYZ", ...}
2. Call prepare_relay → get $KEY (valid 1 hour)
3. bash_tool (returns immediately):
     ( for i in $(seq 1 40); do
         code=$(curl -s -o /tmp/task_XYZ.json -w '%{http_code}' \
           -H "Authorization: Bearer $KEY" \
           "https://maestro.yourdomain.dev/tasks/XYZ/result")
         [ "$code" = "200" ] && break
         sleep 15
       done ) &
     echo "watcher launched"
4. Conversation continues — both parties free.
5. On demand: cat /tmp/task_XYZ.json (or: read_output <output_file>)
```

### 4. Dispatch Guard
`exec` and `script` reject commands that look like raw agent CLI invocations (regex: `\b(codex|gemini|claude)\b.*(?:-[pq]|--prompt|--model|--message)`). These must go through the dedicated dispatch tools (`codex`, `gemini`, `claude`) so that Maestro applies the `AGENT_SCOPE_PREFIX`, records the task in the ledger, and builds the correct CLI arguments.

### 5. Local Self-Reference Guard (stdio only)
When running in stdio transport mode, `exec`, `script`, `read`, and `write` reject commands targeting the local host. The agent should use native Bash/filesystem tools instead. This guard does NOT apply to HTTP transport (Claude.ai sessions).

### 6. State Persistence
- **OAuth state** (clients, access/refresh tokens) → `~/.maestro/oauth_state.json`
- **Task registry** (runtime task state) → `~/.maestro/task_registry.json`
- **Task ledger** (persistent task history) → `~/.maestro/task_ledger.json`

All use atomic write-to-tmp-and-replace to prevent corruption.

### 7. Context Budget Awareness
Tool responses consume LLM context tokens.
- **Surgical Reads:** Use `read` with `head` or `tail` parameters.
- **Large Files:** Use `transfer` or the relay (`prepare_relay` + curl push/pull); the response is just an `[OK]`.
- **Orchestra Output:** Agent output is saved to disk; only a preview (max 1500 chars) is returned. Use `read_output` for targeted inspection with line ranges.
- **Task Results:** Retrieve via HTTP (`result_url` from `poll`) or `read_output` — never through `poll` itself.
- **Avoid `maestro_read` on large files.** Use `exec` + grep/head/sed for surgical extraction.

### 8. Scope Prefix
All agent dispatch tools prepend `AGENT_SCOPE_PREFIX` to prompts, directing agents to read `~/Development/General/AGENTS.md` for fleet conduct rules before starting work.

## Engineering Standards

- **Error Handling:** Structured JSON errors with categories: `validation_error`, `agent_dispatch_bypass`, `local_self_reference`, `ssh_timeout`, `transport_error`, `ssh_connection_failed`. Transient SSH failures are retried (3 attempts, exponential backoff from 1s).
- **Security:** Never log or commit secrets. Use the PIN gate (`MAESTRO_AUTHORIZE_PIN_HASH`) for remote access. Transfer relay validates paths against allowed dirs and rejects system directories.
- **Cross-Platform:** Always check `config.shell` before generating commands. Use `_ps_quote` for PowerShell.
- **Atomicity:** All state stores use write-to-tmp-and-replace to prevent corruption.
- **Dispatch Hygiene:** Agent CLIs must be invoked through orchestra dispatch tools, never through `exec`/`script`. The dispatch guard enforces this at runtime.

## Development

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
python server.py --transport stdio

# Test
pytest tests/
```

## Deployment (Hub)

Maestro runs as a Docker container on the Hub (NAS appliance, 198.51.100.2).
The Hub is the fleet hub (`is_local: true`). All other hosts are SSH targets.

```
/volume2/docker/maestro/
├── repo/          # git clone (Dockerfile, docker-compose.yml, source)
├── config/        # .env, hosts.yaml, ssh/, cloudflared/
└── state/         # Persistent: oauth_state.json, task_ledger.json, task_registry.json
```

```bash
# Update + rebuild
cd /volume2/docker/maestro/repo
git pull && docker compose up -d --build

# Restart (ALWAYS both containers)
docker compose restart
```

Wait 15–30s after rebuild and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.

## Environment Variables

All configuration is via environment variables, loaded from `.env` (on the Hub: `/volume2/docker/maestro/config/.env`).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MAESTRO_ISSUER_URL` | **Yes (HTTP)** | `https://localhost:8222` | Public URL for OAuth discovery. Without this, remote clients can't authenticate. |
| `MAESTRO_AUTHORIZE_PIN_HASH` | **Yes (HTTP)** | — | SHA-256 hex digest of your approval PIN. Required for the PIN-gate consent flow. |
| `MAESTRO_TRANSFER_TOKEN` | Yes | — | Master secret for daily-rotating HMAC transfer auth. Never used as a bearer token directly — agents derive ephemeral tokens via `prepare_relay`. |
| `MAESTRO_TRUSTED_CLIENT_IDS` | No | — | Comma-separated OAuth client IDs that auto-approve without PIN prompt. |
| `MAESTRO_LAN_ORIGINS` | No | — | LAN origins for OAuth URL rewriting (format: `host:port=scheme`). |
| `MAESTRO_TRANSFER_ALLOWED_DIRS` | No | `~/` | Comma-separated dirs that transfer relay may read/write. |
| `MAESTRO_DEFAULT_REPO` | No | `~/workspace` | Default working directory (vestigial — all dispatch tools require explicit `working_dir`). |
| `MAESTRO_ORCHESTRA_OUTPUT_DIR` | No | `~/.agent-orchestra/outputs` | Directory where agent output files are written. |
| `MAESTRO_OAUTH_STATE_PATH` | No | `~/.maestro/oauth_state.json` | Where OAuth state is persisted across restarts. |
| `MAESTRO_TASK_LEDGER_PATH` | No | `~/.maestro/task_ledger.json` | Where the persistent task ledger is stored. |
| `MAESTRO_CODEX_TIMEOUT` | No | `1800` | Default Codex dispatch timeout in seconds (30 min). |
| `MAESTRO_CLAUDE_TIMEOUT` | No | `1200` | Default Claude Code dispatch timeout in seconds (20 min). |
| `MAESTRO_GEMINI_TIMEOUT` | No | `900` | Default Gemini dispatch timeout in seconds (15 min). |
| `SSH_TIMEOUT` | No | `300` | Default SSH command timeout in seconds. |

## Critical Rules

1. **Don't kill the Maestro container** via Maestro tools — it terminates the connection with no recovery path. Maestro runs on the Hub as a Docker container.
2. **Always use `docker compose restart`** on the Hub (never `docker restart maestro` alone). cloudflared shares maestro's network namespace — restarting maestro alone orphans cloudflared. Wait 15–30s and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.
3. **`MAESTRO_ISSUER_URL` must be set** in the Hub's config `.env`. Without it, OAuth discovery advertises `localhost` and remote clients can't authenticate.
4. **Python default parameter values are evaluated at definition time.** Constants used as defaults must be defined before the functions that reference them.
5. **hosts.yaml is gitignored.** Use `hosts.example.yaml` as a template.
6. **`poll` is status-only.** It returns task metadata (status, times, output_file, result_url). Full results must be retrieved via HTTP (`result_url` + relay token) or `read_output`. Never expect result payloads from `poll`.
7. **Agent dispatch must go through orchestra tools.** Never invoke `codex`, `gemini`, or `claude` CLIs via `exec`/`script`. The dispatch guard will block it.
8. **Transfer relay tokens are valid for 1 hour.** Call `prepare_relay` once per transfer session. Use the returned bearer token for `/transfer/push`, `/transfer/pull`, and `/tasks/{id}/result`.

---

## Naming & Organization
Follow the fleet naming convention: `~/Development/General/docs/fleet-naming-convention.md`.
If in doubt, `cat` it via Maestro or read it locally.

## Agent Conduct
All dispatched agents must read `~/Development/General/AGENTS.md` before starting work.
It contains fleet-wide conduct rules, file hygiene requirements, and pointers to fleet documentation.
```

---

## 3. Itemized Code Changes (agent_status fix)

In `fleet.py`, the `agent_status` function only checks codex and gemini. Add a Claude Code check:

```python
# CURRENT (line ~418):
codex_rc, codex_out = await _orchestra_run_cli(h, "codex --version 2>&1", timeout=10)
gemini_rc, gemini_out = await _orchestra_run_cli(h, "gemini --version 2>&1", timeout=10)

# ADD after gemini check:
claude_rc, claude_out = await _orchestra_run_cli(h, "claude --version 2>&1", timeout=10)

# UPDATE the return JSON to include:
"claude": {"available": claude_rc == 0, "output": claude_out.strip()[:200]},
```
