# Maestro MCP — Developer Guide

Maestro is a multi-host machine fleet orchestration layer and AI agent orchestra, exposed via the Model Context Protocol (MCP). It turns a collection of SSH-accessible machines into a unified workspace with Cellar-local tmux for observation, steering, and completion detection (ADR-0007).

## Architecture

All task execution uses **Cellar-local tmux**: every `run`, `dispatch`, or `service` creates a tmux window on the Cellar that runs `ssh host 'command'` inside it. Maestro observes, steers, and detects completion locally — no network crossing needed.

- **Entry Point (`server.py`):** Configures FastMCP, sets up OAuth, wires modules, and starts the server (stdio or streamable-http).
- **Core Package (`maestro/`):**
    - **`mux.py`:** Cellar-local tmux primitives — `create_task_window`, `wait_for_completion`, `capture_pane`, `send_keys`, `kill_window`, `list_windows`. Output at `/root/.maestro/task_output/`.
    - **`tools/fleet.py`:** Fleet tools: `run`, `read`, `write`, `transfer`, `status`, `observe`, `steer`, `stop`, `service`.
    - **`tools/orchestra.py`:** Orchestra tools: `dispatch`, `tasks`, `read_output`, `prepare_relay`. Plus task ledger, auto-promote, scope prefix, agent output management.
    - **`hosts.py`:** Fleet topology management and `hosts.yaml` parsing. Per-host `allowed_dirs` enforcement.
    - **`transport.py`:** Persistent SSH ControlMaster lifecycle.
    - **`local.py`:** Zero-overhead execution for the hub machine (`is_local: true`).
    - **`relay.py`:** HTTP endpoints for file transfers and task result retrieval.
    - **`client.py`:** Client classification and per-client execution profiles.
    - **`config.py`:** Environment-based configuration (`MaestroConfig`).
    - **`oauth_state.py`:** Atomic JSON persistence for OAuth state.

## Tool Surface (13 tools)

### Fleet I/O (4)

| Tool | Purpose |
|---|---|
| `run` | Execute a command or script on a host. 300s ceiling. Ledger-tracked. |
| `read` | Read a file from a host. Ledger-tracked. |
| `write` | Write a file to a host. Ledger-tracked. |
| `transfer` | SCP file to/from a host. Ledger-tracked. |

### Task Dispatch (2)

| Tool | Purpose |
|---|---|
| `dispatch` | Start codex/gemini/claude (oneshot or interactive). 6h ceiling. |
| `service` | Start a long-running process (vLLM, Jupyter, etc.). No ceiling. |

### Task Lifecycle (5)

| Tool | Purpose |
|---|---|
| `tasks` | Query the ledger. Surfaces overtime flags. Filter by status/agent/host/type. |
| `observe` | Capture live output of a running task (local pane read, zero SSH cost). |
| `steer` | Send input to a running task (logged to output file). |
| `stop` | Kill a task (kills tmux window → SSH → remote process). |
| `read_output` | Read completed task output from Cellar disk. |

### Infrastructure (2)

| Tool | Purpose |
|---|---|
| `status` | Fleet health, auto-reconnect, optional agent CLI discovery (`agents=True`). |
| `prepare_relay` | Ephemeral transfer/task-result token (1h TTL). |

## Key Patterns

### 1. Cellar-Local Tmux (ADR-0007)

Every task is a tmux window on the Cellar. The command inside each window is an SSH session to the target host. Completion is detected via `tmux wait-for` — a zero-CPU synchronization primitive.

```
Cellar tmux window → SSH session → remote process
observe/steer/stop → local tmux operations → relayed through SSH
```

Only Maestro creates tmux sessions. Agents run foreground inside Maestro-owned windows.

### 2. Auto-Promote (block_timeout)

Execution tools use `_auto_promote()` for long-running tasks:
- **Inline:** Try to finish within `block_timeout` (client-dependent: 5s remote, 60s local).
- **Background:** If timeout exceeds, task continues in tmux. Returns `{task_id}`.
- **Monitoring:** Use `observe(task_id)` for live output, `tasks()` for status with overtime flags.

Client profiles (from `client.py`):
- **remote** (Claude.ai via Cloudflare): `block_timeout_agent=0` (always dispatch), `block_timeout_exec=5`
- **local** (localhost): `block_timeout_agent=30`, `block_timeout_exec=60`
- **lan** (10.42.69.*): `block_timeout_agent=10`, `block_timeout_exec=20`
- **stdio** (Claude Code): `block_timeout_agent=30`, `block_timeout_exec=60`

### 3. System-Policy Timeouts

No tool exposes a timeout parameter. Timeouts are set in `MaestroConfig`:
- `run_ceiling = 300` (5 min hard kill)
- `dispatch_ceiling = 21600` (6h, env: `MAESTRO_DISPATCH_CEILING`)
- `service_overtime_advisory = 86400` (24h informational flag)

The `expected_runtime` parameter is a caller hint recorded verbatim in the ledger. Tasks are flagged overtime at exactly the declared value — no hidden multipliers.

### 4. Universal Ledger

Every operation that touches a remote host gets a ledger entry — execution, file I/O, transfers. The `tasks` tool surfaces all entries with overtime flags for running tasks.

Ledger fields: `task_id`, `agent`, `host`, `prompt`, `status`, `task_type`, `expected_runtime`, `client_class`, `dispatched_at`, `completed_at`, `return_code`, `output_file`, `result_url`.

### 5. Agent Supervision

Two modes for `dispatch`:
- **Oneshot** (default): Agent receives prompt via CLI flag, runs autonomously.
- **Interactive**: Agent starts bare. Drive via alternating `observe`/`steer` calls.

### 6. Dispatch Guard

`run` rejects commands that look like raw agent CLI invocations (regex pattern). Use `dispatch` instead.

### 7. Double-Entry Output

Agent outputs live on both the target machine (project history, indefinite) and the Cellar (replica, 90-day retention). Either copy can recover the other.

### 8. Context Budget Awareness

Tool responses consume LLM context tokens.
- **Surgical Reads:** Use `read` with `head` or `tail` parameters.
- **Large Files:** Use `transfer` or the relay (`prepare_relay` + curl push/pull).
- **Orchestra Output:** Only a preview (max 1500 chars) is returned inline. Use `read_output` for targeted inspection.
- **Task Results:** Retrieve via HTTP (`result_url`) or `read_output`.

### 9. Scope Prefix

All agent dispatches prepend `AGENT_SCOPE_PREFIX`, directing agents to read `~/Development/General/AGENTS.md` for fleet conduct rules.

## Deployment (Cellar)

Maestro runs as a Docker container on the Cellar (TrueNAS SCALE, 10.42.69.2). The Cellar is the fleet hub (`is_local: true`). All other hosts are SSH targets.

**Development** happens on Apollyon (`/home/rmstxrx/Development/maestro-mcp`). The Cellar repo (`/volume2/docker/maestro/repo`) is a **read-only deployment target** — it only pulls from GitHub and rebuilds. No agent may be dispatched with `working_dir` pointing to the Maestro repo on the Cellar.

```
Apollyon (dev)                    GitHub                    Cellar (deploy)
  edit + commit
  git push origin main    →    origin/main    ←    git pull
                                                  docker compose build --no-cache
                                                  docker compose up -d --force-recreate
```

```
/volume2/docker/maestro/
├── repo/          # git clone (Dockerfile, docker-compose.yml, source)
├── config/        # .env, hosts.yaml, ssh/, cloudflared/
└── state/         # Persistent: oauth_state.json, task_ledger.json, task_output/
```

Task output persists at `state/task_output/` via the Docker volume mount `../state:/root/.maestro`.

```bash
# Deploy from Cellar (after pushing from Apollyon)
cd /volume2/docker/maestro/repo
git pull && docker compose build --no-cache && docker compose up -d --force-recreate
```

Wait 15-30s after rebuild and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.

## Critical Rules

1. **Don't kill the Maestro container** via Maestro tools — it terminates the connection with no recovery path.
2. **Always use `docker compose restart`** — cloudflared shares maestro's network namespace.
3. **`MAESTRO_ISSUER_URL` must be set** in the Cellar's config `.env`.
4. **Agent dispatch must go through `dispatch`.** Never invoke agent CLIs via `run`. The dispatch guard will block it.
5. **Transfer relay tokens are valid for 1 hour.** Call `prepare_relay` once per session.
6. **Only Maestro creates tmux sessions.** No tool creates remote tmux sessions.
7. **Timeouts are system policy.** `expected_runtime` is an honest declaration, not a control parameter.
8. **hosts.yaml is gitignored.** Use `hosts.example.yaml` as a template.

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MAESTRO_ISSUER_URL` | **Yes (HTTP)** | `https://localhost:8222` | Public URL for OAuth discovery. |
| `MAESTRO_AUTHORIZE_PIN_HASH` | **Yes (HTTP)** | — | SHA-256 hex digest of approval PIN. |
| `MAESTRO_TRANSFER_TOKEN` | Yes | — | Master secret for HMAC transfer auth. |
| `MAESTRO_DISPATCH_CEILING` | No | `21600` | Agent dispatch hard ceiling (seconds). |
| `MAESTRO_MAX_TASKS_PER_HOST` | No | `10` | Soft per-host concurrent task limit. |
| `MAESTRO_TRUSTED_CLIENT_IDS` | No | — | Comma-separated auto-approve client IDs. |
| `MAESTRO_LAN_ORIGINS` | No | — | LAN origins for OAuth URL rewriting. |
| `MAESTRO_TRANSFER_ALLOWED_DIRS` | No | `~/` | Dirs that transfer relay may access. |
| `MAESTRO_ORCHESTRA_OUTPUT_DIR` | No | `~/.maestro/outputs` | Agent output directory. |
| `MAESTRO_TASK_LEDGER_PATH` | No | `~/.maestro/task_ledger.json` | Persistent task ledger. |
| `SSH_TIMEOUT` | No | `300` | Default SSH command timeout. |

## Naming & Organization

Follow the fleet naming convention: `~/Development/General/docs/fleet-naming-convention.md`. Three domains:
- **Maestro** — The system. The MCP server and everything it governs.
- **Orchestra** — The performers. AI agents and their coordination.
- **Fleet** — The infrastructure. Physical/virtual machines, SSH transport, file operations.

## Agent Conduct

All dispatched agents must read `~/Development/General/AGENTS.md` before starting work.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python server.py --transport stdio
pytest tests/
```
