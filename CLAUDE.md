# DORMANT — Maestro v1 (maestro-mcp) superseded by Maestro v2

> **This repo is the archived v1 of the Maestro orchestrator. Active
> development happens in `~/Development/maestro/` (v2). Do not develop here.**
>
> Dormant as of: 2026-04-14.

See `STATE.md` for the v1→v2 migration pointers. The guide below is preserved
for reference — much of the v1 design carried forward into v2 unchanged.

---

# Maestro MCP — Developer Guide (v1, historical)

Maestro is a multi-host machine fleet orchestration layer and AI agent orchestra, exposed via the Model Context Protocol (MCP). It runs inside a Docker container on Cellar and uses Hub-local tmux for all task execution and tracking.

## Architecture

All task execution uses Hub-local tmux: every `run_task(...)` and `dispatch_agent(...)` creates a tmux window on the Hub. Commands are staged into `/tmp/maestro/inbox/`, executed inside SSH sessions, and tracked in the persistent ledger.

- **Entry Point (`server.py`):** Configures FastMCP, sets up OAuth, wires modules, and starts the server.
- **`maestro/mux.py`:** Hub-local tmux primitives (`stage_script`, `create_task_window`, `wait_for_completion`, `kill_window`).
- **`maestro/tools/fleet.py`:** Fleet tools: `run_task`, `read_file`, `write_file`, `orchestra_status`, `stop_task`.
- **`maestro/tools/orchestra.py`:** Orchestra tools: `dispatch_agent`, `current_tasks`, `read_task_output`, `transfer_pull_file`, `transfer_push_file`, `prepare_relay`. Also owns the task registry, task ledger, auto-promote, and scope prefix.
- **`maestro/relay.py`:** HTTP transfer handlers, bearer auth, ephemeral tokens, and server-side staging for out-of-band downloads/uploads.
- **`maestro/task_result.py`:** `/tasks/{id}/result` HTTP handler.
- **`maestro/hosts.py`:** Fleet topology, host registry, allowed-dir enforcement, shell-aware command wrapping.
- **`maestro/transport.py`:** SSH ControlMaster lifecycle and SCP helpers.
- **`maestro/local.py`:** Zero-overhead local execution for the hub host (`is_local: true`).
- **`maestro/client.py`:** Client classification and per-client block timeout profiles.
- **`maestro/config.py`:** Environment-backed configuration (`MaestroConfig`).
- **`maestro/oauth_state.py`:** Atomic JSON persistence for OAuth state.

## Cellar vs Maestro

Cellar is the NAS hardware. Maestro is the Docker container running on Cellar. These are not the same thing.

Task output, the task ledger, and relay staging live inside the Maestro container. Tools like `current_tasks`, `read_task_output`, and `transfer_pull_file` exist so callers never need to reason about container paths directly.

## Tool Surface (11 tools)

### Quick Reference Card

| Category | Tool | Use when |
|---|---|---|
| File I/O | `read_file` | Quick inline peek at a remote file, up to 16 KB. |
| File I/O | `write_file` | Quick inline write of small text content, up to 16 KB. |
| File I/O | `transfer_pull_file` | Pull any larger file out-of-band via a ready-made curl command. |
| File I/O | `transfer_push_file` | Push any larger local file out-of-band via a ready-made curl command. |
| Task Lifecycle | `run_task` | Execute a command or pre-staged script on a host, always through tmux. |
| Task Lifecycle | `stop_task` | Stop a running task, optionally graceful with `graceful=True`. |
| Task Lifecycle | `current_tasks` | Query recent ledger entries and running-task status. |
| Task Lifecycle | `read_task_output` | Preview, tail, head, or download captured task output by `task_id`. |
| Orchestration | `dispatch_agent` | Launch Codex, Gemini, or Claude as a background task. |
| Orchestration | `orchestra_status` | Fleet connectivity and optional agent CLI availability checks. |
| Infrastructure | `prepare_relay` | Get a raw relay token for direct HTTP workflows not covered by the transfer tools. |

## Decision Trees

### Reading a file from a fleet host

```text
Need to peek at contents and reason about them inline?
  <= 16 KB  -> read_file(host, path)
  > 16 KB   -> transfer_pull_file(host, path) -> run curl -> view locally

Need the file in this sandbox (to edit, diff, or push elsewhere)?
  Any size  -> transfer_pull_file(host, path) -> run curl
```

### Writing a file to a fleet host

```text
Small inline content already in context?
  <= 16 KB  -> write_file(host, path, content)

Larger, or file already on disk in this sandbox?
  Any size  -> transfer_push_file(host, path) -> fill in local path -> run curl
```

### Getting task output

```text
Need task status?
  -> current_tasks(status="running")

Need a quick look?
  -> read_task_output(task_id)
  -> read_task_output(task_id, tail=50)

Need the full output file in this sandbox?
  -> read_task_output(task_id, full=True)
     Returns a curl command. No file bytes enter MCP context.
```

### Running things

```text
Quick command (git status, ls, cat)?
  -> run_task(host, command="git status")
     Returns inline if it finishes within the client block timeout,
     else returns {task_id}

Long script already staged in /tmp/maestro/inbox/?
  -> run_task(host, task_id="abc123")

Long-running service (vLLM, Jupyter, training loop)?
  -> run_task(host, command="...", persistent=True, capture=True, label="vllm")

Need an AI agent instead of a shell command?
  -> dispatch_agent(host, agent="codex", prompt="...", working_dir="...")
```

## Key Patterns

### 1. Hub-Local Tmux (ADR-0007)

Every task is a tmux window on the Hub. The command inside the window is an SSH session to the target host. Completion is detected locally with `tmux wait-for`.

### 2. Auto-Promote (block_timeout)

- `run_task(..., persistent=False)` tries to finish inline within `block_timeout_exec`, then auto-promotes into the registry if it runs longer.
- `run_task(..., persistent=True)` always returns immediately with a `task_id`.
- `dispatch_agent(...)` always returns immediately with a `task_id`.
- Monitor with `current_tasks` and inspect output with `read_task_output`.

Client profiles from `client.py`:

- `remote`: `block_timeout_agent=0`, `block_timeout_exec=5`
- `local`: `block_timeout_agent=30`, `block_timeout_exec=60`
- `lan`: `block_timeout_agent=10`, `block_timeout_exec=20`
- `stdio`: `block_timeout_agent=30`, `block_timeout_exec=60`

### 3. System-Policy Timeouts

- `run_ceiling = 300` for non-persistent `run_task`
- `dispatch_ceiling = 21600` (6h) for `dispatch_agent`
- `service_overtime_advisory = 86400` (24h) for persistent tasks

`expected_runtime` is recorded as caller-declared metadata. It is not a caller-controlled timeout.

### 4. Universal Ledger

Every remote operation that becomes a tracked task records metadata in the task ledger. `current_tasks` hides container-internal paths and exposes task-oriented guidance instead.

### 5. Files Never Pass Through MCP

`transfer_pull_file`, `transfer_push_file`, and `read_task_output(full=True)` return curl commands only. File bytes stay on HTTP, not in MCP tool results.

### 6. Dispatch Guard

`run_task` rejects raw `codex`, `gemini`, or `claude` CLI dispatches that look like agent launches. Use `dispatch_agent` instead.

### 7. Context Budget Awareness

- Use `read_file` / `write_file` only for small inline text.
- Use `transfer_pull_file` / `transfer_push_file` for anything larger or binary.
- Use `read_task_output` for previews and targeted reads.
- Use `read_task_output(full=True)` when the whole output file is needed locally.

### 8. Scope Prefix

All agent dispatches prepend `AGENT_SCOPE_PREFIX`, directing agents to read `~/Development/General/AGENTS.md` before they start.

## Deployment (Hub)

Maestro runs as a Docker container on the Hub (Cellar, `is_local: true`). The repo on Cellar is a deployment target, not a development workspace.

```text
GPU-server (dev)                  GitHub                    Hub (deploy)
  edit + commit
  git push origin main    ->    origin/main    <-    git pull
                                                 docker compose build --no-cache
                                                 docker compose up -d --force-recreate
```

```text
/volume2/docker/maestro/
|- repo/          # git clone (Dockerfile, docker-compose.yml, source)
|- config/        # .env, hosts.yaml, ssh/, cloudflared/
`- state/         # Persistent: oauth_state.json, task_ledger.json, task_output/
```

Task output persists through the Docker volume mount `../state:/root/.maestro`.

```bash
cd /volume2/docker/maestro/repo
git pull && docker compose build --no-cache && docker compose up -d --force-recreate
```

Wait 15-30s after rebuild and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.

## Critical Rules

1. **Do not kill the Maestro container** via Maestro tools. That terminates the MCP connection.
2. **Use `docker compose restart` when restarting services.** `cloudflared` shares Maestro's network namespace.
3. **`MAESTRO_ISSUER_URL` must be set** for HTTP mode.
4. **Agent dispatch must go through `dispatch_agent`.** Never invoke agent CLIs via `run_task`.
5. **Prefer `transfer_pull_file` and `transfer_push_file`.** `prepare_relay` is for direct HTTP or custom workflows.
6. **Only Maestro creates tmux sessions.** Agents never create remote tmux.
7. **Timeouts are system policy.** `expected_runtime` is a declaration, not a knob.
8. **`hosts.yaml` is gitignored.** Use `hosts.example.yaml` as the template.

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MAESTRO_ISSUER_URL` | **Yes (HTTP)** | `https://localhost:8222` | Public URL for OAuth discovery and relay URLs. |
| `MAESTRO_AUTHORIZE_PIN_HASH` | **Yes (HTTP)** | — | SHA-256 hex digest of the approval PIN. |
| `MAESTRO_TRANSFER_TOKEN` | Yes | — | Master secret for relay auth. |
| `MAESTRO_DISPATCH_CEILING` | No | `21600` | Agent dispatch hard ceiling in seconds. |
| `MAESTRO_MAX_TASKS_PER_HOST` | No | `10` | Soft per-host concurrency limit. |
| `MAESTRO_TRUSTED_CLIENT_IDS` | No | — | Comma-separated auto-approved OAuth client IDs. |
| `MAESTRO_LAN_ORIGINS` | No | — | LAN origins allowed for OAuth URL rewriting. |
| `MAESTRO_TRANSFER_ALLOWED_DIRS` | No | `~/` | Allowed local paths for relay reads/writes. |
| `MAESTRO_TASK_LEDGER_PATH` | No | `~/.maestro/task_ledger.json` | Persistent task ledger path. |
| `SSH_TIMEOUT` | No | `300` | Default SSH command timeout. |

## Naming & Organization

Follow the fleet naming convention in `~/Development/General/docs/fleet-naming-convention.md`.

- **Maestro**: the MCP server and orchestration system.
- **Orchestra**: the agents and task supervision layer.
- **Fleet**: the machines, SSH transport, and file operations.

## Agent Conduct

All dispatched agents must read `~/Development/General/AGENTS.md` before starting work.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py --transport stdio
pytest tests/ -v
```
