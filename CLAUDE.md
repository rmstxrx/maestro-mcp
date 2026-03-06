# Maestro MCP

Multi-host machine fleet + AI agent orchestra, exposed as an MCP server.

## Architecture

- **server.py** (~2200 lines) — main MCP server. Hosts all tools, OAuth wiring,
  transfer relay, and agent orchestra. Monolithic by design: single-file
  deployment, no internal package structure.
- **maestro_oauth.py** — Custom OAuth provider (PIN-based approval flow).
- **oauth_rewrite.py** — ASGI middleware for LAN/localhost OAuth URL rewriting.
- **hosts.yaml** — Fleet topology (gitignored, contains real hostnames/aliases).
- **hosts.example.yaml** — Template for hosts.yaml.

## Key Patterns

### Auto-Promote (block_timeout)

All execution tools (`maestro_exec`, `maestro_script`, `codex_execute`,
`gemini_analyze`, `gemini_execute`, `gemini_research`, `claude_execute`)
use the `_auto_promote()` pattern:

- Try to complete inline within `block_timeout` (default 20s)
- If exceeded, promote to background task via `asyncio.shield()`
- Return `{"auto_promoted": true, "task_id": "..."}` instead of blocking
- Caller uses `agent_poll(task_id, wait=N)` to long-poll the result

The `_dispatch` variants (`codex_dispatch`, `gemini_dispatch`, `claude_dispatch`)
are thin wrappers that call the corresponding `_execute` with `block_timeout=0`.

### Transfer Relay

HTTP endpoints (`/transfer/push`, `/transfer/pull`) for zero-context-cost file
transfers between sandboxed containers and fleet hosts. Authenticated via static
bearer token (separate from OAuth).

### SSH ControlMaster

All remote hosts are reached via persistent SSH ControlMaster connections.
Connections are warmed on startup and torn down on shutdown. Transient failures
trigger retry with exponential backoff + connection teardown/rebuild.

## Environment Variables

- `MAESTRO_ISSUER_URL` — **Required.** Public URL for OAuth discovery
  (e.g., `https://maestro.rmstxrx.dev`). Without this, OAuth advertises
  localhost and remote clients can't authenticate.
- `SSH_TIMEOUT` — Default SSH command timeout (default: 300).
- `MAESTRO_DEFAULT_REPO` — Default working directory for agent CLIs.
- `MAESTRO_LAN_ORIGINS` — Comma-separated LAN origins for OAuth URL rewriting.
- `TRANSFER_BEARER_TOKEN` — Static token for transfer relay authentication.

## Development

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run locally (streamable-http, default)
MAESTRO_ISSUER_URL=http://localhost:8222 python server.py

# Run tests
pytest tests/
```

## Critical Rules

1. **Never kill the Maestro process via Maestro tools** — doing so locks out
   the session entirely (the tool that issued the kill loses its own server).

2. **BLOCK_TIMEOUT_DEFAULT must be defined before any function that uses it as
   a default parameter.** Python evaluates defaults at definition time. Moving
   it to the orchestra constants section (after the functions) causes a
   NameError crash on startup.

3. **hosts.yaml is gitignored** — it contains real fleet topology. Use
   hosts.example.yaml as a template.

4. **docs/ contents are gitignored** — sensitive session logs were historically
   stored there. Use `journal/` for session logs (committed to repo).

5. **The repo is public** — never commit credentials, topology details, or
   bearer tokens. Scrub git history if accidentally committed.

## File Layout

```
server.py              — Main MCP server (all tools + orchestra)
maestro_oauth.py       — OAuth provider with PIN-based approval
oauth_rewrite.py       — ASGI middleware for LAN OAuth URL rewriting
hosts.yaml             — Fleet topology (gitignored)
hosts.example.yaml     — Template
journal/               — Session logs (committed)
tests/                 — pytest tests
docs/                  — Gitignored working docs
```
