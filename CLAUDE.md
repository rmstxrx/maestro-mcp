# Maestro MCP — Developer Guide

Maestro is a multi-host machine fleet orchestration layer and AI agent orchestra, exposed via the Model Context Protocol (MCP). It turns a collection of SSH-accessible machines into a unified workspace.

## Architecture

Maestro is a modular Python package with a slim entry point:

- **Entry Point (`server.py`):** Configures FastMCP, sets up OAuth, wires modules, and starts the server (stdio or streamable-http).
- **Core Package (`maestro/`):**
    - **`tools/fleet.py`:** Core fleet operations: `exec`, `script`, `read`, `write`, `transfer`, `status`.
    - **`tools/orchestra.py`:** Agent dispatch (`codex`, `gemini`, `claude`), task registry, and auto-promote logic.
    - **`hosts.py`:** Fleet topology management and `hosts.yaml` parsing. Supports Bash and PowerShell.
    - **`transport.py`:** Persistent SSH ControlMaster lifecycle (warmup, teardown, transient failure retries).
    - **`local.py`:** Zero-overhead execution for the "hub" (is_local: true) machine.
    - **`relay.py`:** HTTP endpoints for high-speed file transfers bypassing the LLM context.
    - **`oauth_state.py`:** Atomic JSON persistence for OAuth clients and tokens (survives restarts).
    - **`config.py`:** Environment-based configuration (MaestroConfig).

## Key Patterns

### 1. Auto-Promote (block_timeout)
Execution tools use `_auto_promote()` to handle long-running tasks:
- **Inline:** Try to finish within `block_timeout` (client-dependent: 30s local, 0s remote).
- **Background:** If timeout exceeds, tasks are shielded and moved to `TASK_REGISTRY`.
- **Polling:** Returns a `task_id`. Use `poll(task_id)` to get the final result.

### 2. State Persistence
OAuth state (clients, access/refresh tokens) is persisted to `~/.maestro/oauth_state.json`. This ensures that active sessions and registered clients are **not** lost when the Maestro service restarts.

### 3. Context Budget Awareness
Tool responses consume LLM context tokens.
- **Surgical Reads:** Use `read` with `head` or `tail` parameters.
- **Large Files:** Use `transfer` to move files to the hub machine; the response is just an `[OK]`.
- **Orchestra Output:** Agent output is saved to disk; only a preview is returned. Use `read_output` for targeted inspection.

## Engineering Standards

- **Error Handling:** Distinguish between transient SSH failures (retried) and permanent errors (reported).
- **Security:** Never log or commit secrets. Use the PIN gate (`MAESTRO_AUTHORIZE_PIN_HASH`) for remote access.
- **Cross-Platform:** Always check `config.shell` before generating commands. Use `_ps_quote` for PowerShell.
- **Atomicity:** `OAuthStateStore` uses a write-to-tmp-and-replace strategy to prevent state corruption.

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

## Environment Variables

All configuration is via environment variables, typically loaded from `.env` by systemd `EnvironmentFile`.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `MAESTRO_ISSUER_URL` | **Yes (HTTP)** | `https://localhost:8222` | Public URL for OAuth discovery. Without this, remote clients can't authenticate. |
| `MAESTRO_AUTHORIZE_PIN_HASH` | **Yes (HTTP)** | — | SHA-256 hex digest of your approval PIN. Required for the PIN-gate consent flow. |
| `MAESTRO_TRANSFER_TOKEN` | Yes | — | Master secret for daily-rotating HMAC transfer auth. Never used as a bearer token directly — agents must derive daily tokens from it. |
| `MAESTRO_TRUSTED_CLIENT_IDS` | No | — | Comma-separated OAuth client IDs that auto-approve without PIN prompt. |
| `MAESTRO_LAN_ORIGINS` | No | — | LAN origins for OAuth URL rewriting (format: `host:port=scheme`, e.g. `10.0.0.1:8222=http`). |
| `MAESTRO_TRANSFER_ALLOWED_DIRS` | No | `~/` | Comma-separated dirs that transfer relay may read/write. |
| `MAESTRO_DEFAULT_REPO` | No | `~/workspace` | Default working directory for agent CLI tools. |
| `MAESTRO_ORCHESTRA_OUTPUT_DIR` | No | `~/.agent-orchestra/outputs` | Directory where agent output files are written. |
| `MAESTRO_OAUTH_STATE_PATH` | No | `~/.maestro/oauth_state.json` | Where OAuth state is persisted across restarts. |
| `SSH_TIMEOUT` | No | `300` | Default SSH command timeout in seconds. |

## Critical Rules

1. **Don't kill the Maestro process** via Maestro tools — it terminates the connection with no recovery path.
2. **`sudo systemctl restart maestro` drops the active OAuth session.** Wait 15–30s and poll `/.well-known/oauth-authorization-server` for HTTP 200 before issuing tool calls.
3. **`MAESTRO_ISSUER_URL` must be set** before starting in HTTP mode. Without it, OAuth discovery advertises `localhost` and remote clients can't authenticate. Always start via systemd so `EnvironmentFile` is respected.
4. **Python default parameter values are evaluated at definition time.** Constants used as defaults must be defined before the functions that reference them.
5. **hosts.yaml is gitignored.** Use `hosts.example.yaml` as a template.
6. **Transfer token derivation:** `import hmac,hashlib,time; hmac.new(SECRET.encode(),str(int(time.time())//86400).encode(),hashlib.sha256).hexdigest()`. The server accepts current and previous daily window.
