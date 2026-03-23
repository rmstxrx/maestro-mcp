# Maestro MCP — Developer Guide

Maestro is a multi-host machine fleet orchestration layer and AI agent orchestra, exposed via the Model Context Protocol (MCP). It turns a collection of SSH-accessible machines into a unified workspace.

## Architecture

Maestro is a modular Python package with a slim entry point:

- **Entry Point (`server.py`):** Configures FastMCP, sets up OAuth, wires modules, and starts the server (stdio or streamable-http).
- **Core Package (`maestro/`):**
    - **`tools/fleet.py`:** Fleet operations (`exec`, `script`, `read`, `write`, `transfer`, `status`), task querying (`tasks`, `poll`), relay (`prepare_relay`), dispatch guard, and discovery tools.
    - **`tools/orchestra.py`:** Agent dispatch (`codex`, `gemini`, `claude`), task registry, task ledger, auto-promote logic, and agent output management.
    - **`hosts.py`:** Fleet topology management and `hosts.yaml` parsing. Supports Bash and PowerShell.
    - **`transport.py`:** Persistent SSH ControlMaster lifecycle (warmup, teardown, transient failure retries).
    - **`local.py`:** Zero-overhead execution for the "hub" (is_local: true) machine.
    - **`relay.py`:** HTTP endpoints for file transfers and task result retrieval, bypassing the LLM context.
    - **`oauth_state.py`:** Atomic JSON persistence for OAuth clients and tokens (survives restarts).
    - **`config.py`:** Environment-based configuration (MaestroConfig).

## Key Patterns

### 1. Auto-Promote (block_timeout)
Execution tools use `_auto_promote()` to handle long-running tasks:
- **Inline:** Try to finish within `block_timeout` (client-dependent: 30s local, 0s remote).
- **Background:** If timeout exceeds, tasks are shielded and moved to `TASK_REGISTRY`.
- **Monitoring:** Returns a `task_id`. Use `poll(task_id)` for status metadata. Use the HTTP endpoint or `read_output` for full results — `poll` never returns result payloads.

### 2. Task Ledger
Every dispatched task is recorded in a persistent, append-only ledger (`~/.maestro/task_ledger.json`). The ledger tracks: `task_id`, `agent`, `host`, `prompt`, `status`, `client_class`, `dispatched_at`, `completed_at`, `return_code`, `output_file`, and `result_url`. The ledger survives both task eviction and Maestro restarts (orphaned tasks are marked accordingly). Query it with the `tasks` tool.

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
`exec` and `script` reject commands that look like raw agent CLI invocations (e.g., `codex -p "..."` or `gemini --model ... -p "..."`). These must go through the dedicated dispatch tools (`codex`, `gemini`, `claude`) so that Maestro applies the `AGENT_SCOPE_PREFIX`, records the task in the ledger, and builds the correct CLI arguments.

### 5. State Persistence
- **OAuth state** (clients, access/refresh tokens) → `~/.maestro/oauth_state.json`
- **Task registry** (runtime task state) → `~/.maestro/task_registry.json`
- **Task ledger** (persistent task history) → `~/.maestro/task_ledger.json`

All use atomic write-to-tmp-and-replace to prevent corruption.

### 6. Context Budget Awareness
Tool responses consume LLM context tokens.
- **Surgical Reads:** Use `read` with `head` or `tail` parameters.
- **Large Files:** Use `transfer` or the relay (`prepare_relay` + curl push/pull); the response is just an `[OK]`.
- **Orchestra Output:** Agent output is saved to disk; only a preview is returned. Use `read_output` for targeted inspection.
- **Task Results:** Retrieve via HTTP (`result_url` from `poll`) or `read_output` — never through `poll` itself.

## Engineering Standards

- **Error Handling:** Distinguish between transient SSH failures (retried) and permanent errors (reported).
- **Security:** Never log or commit secrets. Use the PIN gate (`MAESTRO_AUTHORIZE_PIN_HASH`) for remote access.
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
└── state/         # Persistent: oauth_state.json, task_ledger.json, task_registry.json
```

```bash
# Update + rebuild
cd /volume2/docker/maestro/repo
git pull && docker compose up -d --build

# Restart (ALWAYS both containers)
docker compose restart
```

## Environment Variables

All configuration is via environment variables, loaded from `.env` (on the Cellar: `/volume2/docker/maestro/config/.env`).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MAESTRO_ISSUER_URL` | **Yes (HTTP)** | `https://localhost:8222` | Public URL for OAuth discovery. Without this, remote clients can't authenticate. |
| `MAESTRO_AUTHORIZE_PIN_HASH` | **Yes (HTTP)** | — | SHA-256 hex digest of your approval PIN. Required for the PIN-gate consent flow. |
| `MAESTRO_TRANSFER_TOKEN` | Yes | — | Master secret for daily-rotating HMAC transfer auth. Never used as a bearer token directly — agents must derive daily tokens from it. |
| `MAESTRO_TRUSTED_CLIENT_IDS` | No | — | Comma-separated OAuth client IDs that auto-approve without PIN prompt; loaded into `MaestroConfig.trusted_client_ids`. |
| `MAESTRO_LAN_ORIGINS` | No | — | LAN origins for OAuth URL rewriting (format: `host:port=scheme`, e.g. `10.0.0.1:8222=http`). |
| `MAESTRO_TRANSFER_ALLOWED_DIRS` | No | `~/` | Comma-separated dirs that transfer relay may read/write. |
| `MAESTRO_DEFAULT_REPO` | No | `~/workspace` | Default working directory for agent CLI tools. |
| `MAESTRO_ORCHESTRA_OUTPUT_DIR` | No | `~/.agent-orchestra/outputs` | Directory where agent output files are written. |
| `MAESTRO_OAUTH_STATE_PATH` | No | `~/.maestro/oauth_state.json` | Where OAuth state is persisted across restarts. |
| `MAESTRO_TASK_LEDGER_PATH` | No | `~/.maestro/task_ledger.json` | Where the persistent task ledger is stored. |
| `SSH_TIMEOUT` | No | `300` | Default SSH command timeout in seconds. |

## Critical Rules

1. **Don't kill the Maestro container** via Maestro tools — it terminates the connection with no recovery path. Maestro runs on the Cellar as a Docker container.
2. **Always use `docker compose restart`** on the Cellar (never `docker restart maestro` alone). cloudflared shares maestro's network namespace — restarting maestro alone orphans cloudflared. Wait 15–30s and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.
3. **`MAESTRO_ISSUER_URL` must be set** in the Cellar's config `.env`. Without it, OAuth discovery advertises `localhost` and remote clients can't authenticate. Deployment: `/volume2/docker/maestro/` on the Cellar (repo/, config/, state/).
4. **Python default parameter values are evaluated at definition time.** Constants used as defaults must be defined before the functions that reference them.
5. **hosts.yaml is gitignored.** Use `hosts.example.yaml` as a template.
6. **Transfer token derivation:** `import hmac,hashlib,time; hmac.new(SECRET.encode(),str(int(time.time())//86400).encode(),hashlib.sha256).hexdigest()`. The server accepts current and previous daily window.
7. **`poll` is status-only.** It returns task metadata (status, times, output_file, result_url). Full results must be retrieved via HTTP or `read_output`. Never expect result payloads from `poll`.
8. **Agent dispatch must go through orchestra tools.** Never invoke `codex`, `gemini`, or `claude` CLIs via `exec`/`script`. The dispatch guard will block it. Use the dedicated dispatch tools instead.

---

## Naming & Organization
Follow the fleet naming convention: `~/Development/General/docs/fleet-naming-convention.md`.
If in doubt, `cat` it via Maestro or read it locally.

## Agent Conduct
All dispatched agents must read `~/Development/General/AGENTS.md` before starting work.
It contains fleet-wide conduct rules, file hygiene requirements, and pointers to fleet documentation.
