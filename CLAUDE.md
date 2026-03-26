# Maestro MCP — Developer Guide

Maestro is a multi-host machine fleet orchestration layer and AI agent orchestra, exposed via the Model Context Protocol (MCP). It turns a collection of SSH-accessible machines into a unified workspace.

## Architecture

Maestro is a modular Python package with a slim entry point:

- **Entry Point (`server.py`):** Configures FastMCP, sets up OAuth, wires modules, and starts the server (stdio or streamable-http).
- **Core Package (`maestro/`):**
    - **`tools/fleet.py`:** Fleet tools: `exec`, `script`, `read`, `write`, `transfer`, `status`, `add_host`, `reconnect_host`, `list_ssh_hosts`, `agent_status`, `gemini_sessions`. Mux tools: `mux_start`, `mux_read`, `mux_input`, `mux_stop`, `mux_list`.
    - **`tools/orchestra.py`:** Orchestra tools: `codex`, `gemini`, `claude`, `poll`, `read_output`, `tasks`, `prepare_relay`, plus task registry, task ledger, auto-promote logic, agent output management, CLI runner helpers, scope prefix, and eviction loop.
    - **`hosts.py`:** Fleet topology management and `hosts.yaml` parsing. Supports Bash and PowerShell. Per-host `allowed_dirs` enforcement.
    - **`transport.py`:** Persistent SSH ControlMaster lifecycle (warmup, teardown, transient failure retries with exponential backoff).
    - **`local.py`:** Zero-overhead execution for the hub machine (`is_local: true`).
    - **`relay.py`:** HTTP endpoints for file transfers (`/transfer/push`, `/transfer/pull`) and task result retrieval (`/tasks/{id}/result`), bypassing the LLM context window.
    - **`client.py`:** Client classification (remote/local/lan/stdio) and per-client execution profiles controlling block timeouts and poll cooldowns.
    - **`oauth_state.py`:** Atomic JSON persistence for OAuth clients and tokens (survives restarts).
    - **`config.py`:** Environment-based configuration (`MaestroConfig`).

## Taxonomy

Three domains, strict boundaries:

- **Maestro** — The system. The MCP server and everything it governs. Always use the proper name; never say "orchestrator."
- **Orchestra** — The performers. AI agents (Codex, Gemini, Claude Code) and their coordination: dispatch, scope prefix, task ledger, output management.
- **Fleet** — The infrastructure. Physical and virtual machines, SSH transport, host topology, file operations.

The principle: Musical terms for intelligence. Logistical terms for infrastructure. Maestro conducts both.

Code mapping:
- `tools/fleet.py` — Fleet tools: exec, script, read, write, transfer, status, add_host, reconnect_host, list_ssh_hosts, agent_status, gemini_sessions.
- Mux tools (fleet.py): mux_start, mux_read, mux_input, mux_stop, mux_list — tmux window management on fleet hosts.
- `tools/orchestra.py` — Orchestra tools: codex, gemini, claude, poll, read_output, tasks, prepare_relay. Plus task registry, task ledger, auto-promote, scope prefix, output management.

## Key Patterns

### 1. Auto-Promote (block_timeout)
Execution tools use `_auto_promote()` to handle long-running tasks:
- **Inline:** Try to finish within `block_timeout` (client-dependent: 30s local, 0s remote).
- **Background:** If timeout exceeds, tasks are shielded and moved to `TASK_REGISTRY`.
- **Monitoring:** Returns a `task_id`. Use `poll(task_id)` for status metadata. Use the HTTP endpoint or `read_output` for full results — `poll` never returns result payloads.

Client profiles (from `client.py`):
- **remote** (Claude.ai via Cloudflare): `block_timeout_agent=0` (always dispatch), `block_timeout_exec=5`
- **local** (localhost): `block_timeout_agent=30`, `block_timeout_exec=60`
- **lan** (10.42.69.*): `block_timeout_agent=10`, `block_timeout_exec=20`
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
           "https://maestro.rmstxrx.dev/tasks/XYZ/result")
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
- **Task registry** (runtime task state) → in-memory only during the transition away from disk persistence
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

## Deployment (Cellar)

Maestro runs as a Docker container on the Cellar (TrueNAS SCALE, 10.42.69.2).
The Cellar is the fleet hub (`is_local: true`). All other hosts are SSH targets.

```
/volume2/docker/maestro/
├── repo/          # git clone (Dockerfile, docker-compose.yml, source)
├── config/        # .env, hosts.yaml, ssh/, cloudflared/
└── state/         # Persistent: oauth_state.json, task_ledger.json
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

All configuration is via environment variables, loaded from `.env` (on the Cellar: `/volume2/docker/maestro/config/.env`).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MAESTRO_ISSUER_URL` | **Yes (HTTP)** | `https://localhost:8222` | Public URL for OAuth discovery. Without this, remote clients can't authenticate. |
| `MAESTRO_AUTHORIZE_PIN_HASH` | **Yes (HTTP)** | — | SHA-256 hex digest of your approval PIN. Required for the PIN-gate consent flow. |
| `MAESTRO_TRANSFER_TOKEN` | Yes | — | Master secret for daily-rotating HMAC transfer auth. Never used as a bearer token directly — agents derive ephemeral tokens via `prepare_relay`. |
| `MAESTRO_TRUSTED_CLIENT_IDS` | No | — | Comma-separated OAuth client IDs that auto-approve without PIN prompt. |
| `MAESTRO_LAN_ORIGINS` | No | — | LAN origins for OAuth URL rewriting (format: `host:port=scheme`). |
| `MAESTRO_TRANSFER_ALLOWED_DIRS` | No | `~/` | Comma-separated dirs that transfer relay may read/write. |
| `MAESTRO_DEFAULT_REPO` | No | `~/workspace` | Default working directory (vestigial — all dispatch tools require explicit `working_dir`). |
| `MAESTRO_ORCHESTRA_OUTPUT_DIR` | No | `~/.maestro/outputs` | Directory where agent output files are written. |
| `MAESTRO_OAUTH_STATE_PATH` | No | `~/.maestro/oauth_state.json` | Where OAuth state is persisted across restarts. |
| `MAESTRO_TASK_LEDGER_PATH` | No | `~/.maestro/task_ledger.json` | Where the persistent task ledger is stored. |
| `MAESTRO_CODEX_TIMEOUT` | No | `1800` | Default Codex dispatch timeout in seconds (30 min). |
| `MAESTRO_CLAUDE_TIMEOUT` | No | `1200` | Default Claude Code dispatch timeout in seconds (20 min). |
| `MAESTRO_GEMINI_TIMEOUT` | No | `900` | Default Gemini dispatch timeout in seconds (15 min). |
| `SSH_TIMEOUT` | No | `300` | Default SSH command timeout in seconds. |

## Critical Rules

1. **Don't kill the Maestro container** via Maestro tools — it terminates the connection with no recovery path. Maestro runs on the Cellar as a Docker container.
2. **Always use `docker compose restart`** on the Cellar (never `docker restart maestro` alone). cloudflared shares maestro's network namespace — restarting maestro alone orphans cloudflared. Wait 15–30s and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.
3. **`MAESTRO_ISSUER_URL` must be set** in the Cellar's config `.env`. Without it, OAuth discovery advertises `localhost` and remote clients can't authenticate.
4. **Python default parameter values are evaluated at definition time.** Constants used as defaults must be defined before the functions that reference them.
5. **hosts.yaml is gitignored.** Use `hosts.example.yaml` as a template.
6. **`poll` is status-only.** It returns task metadata (status, times, output_file, result_url). Full results must be retrieved via HTTP (`result_url` + relay token) or `read_output`. Never expect result payloads from `poll`.
7. **Agent dispatch must go through orchestra tools.** Never invoke `codex`, `gemini`, or `claude` CLIs via `exec`/`script`. The dispatch guard will block it.
8. **Transfer relay tokens are valid for 1 hour.** Call `prepare_relay` once per transfer session. Use the returned bearer token for `/transfer/push`, `/transfer/pull`, and `/tasks/{id}/result`.
9. **Claude.ai defers tool loading.** When the MCP connector has many tools, Claude.ai lazy-loads some via Tool Search to save context tokens. Tools are registered server-side and visible in the UI, but the LLM must call `tool_search` to load them before use. This is not a filter or classifier — all tools are available, just deferred. If a Maestro tool seems missing, `tool_search` it.
10. **Transfer relay routes through the Cellar.** The Cellar is the hub with SSH to all hosts. Push and pull requests specify `host` and `remote_path` — the relay handles the Cellar→target SCP hop internally. Never use Apollyon (or any other leaf) as a waypoint. The correct flow: Claude.ai sandbox ↔ relay HTTP ↔ Cellar ↔ SCP to/from target host.

---

## Naming & Organization
Follow the fleet naming convention: `~/Development/General/docs/fleet-naming-convention.md`.
If in doubt, `cat` it via Maestro or read it locally.

## Agent Conduct
All dispatched agents must read `~/Development/General/AGENTS.md` before starting work.
It contains fleet-wide conduct rules, file hygiene requirements, and pointers to fleet documentation.
