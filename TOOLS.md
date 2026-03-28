# Maestro MCP — Tool Reference

## Fleet Tools

### `exec`
Run a command on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name from fleet topology |
| `command` | string | yes | Shell command to execute |
| `cwd` | string | no | Working directory on the host |
| `sudo` | bool | no | Run with sudo (default: false) |

Returns command output. Long-running commands auto-promote to background tasks.

### `script`
Run a multi-line script on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `script` | string | yes | Multi-line script body |
| `cwd` | string | no | Working directory on the host |
| `sudo` | bool | no | Run with sudo (default: false) |

Uses `bash -s` on Linux hosts, `powershell -Command -` on PowerShell hosts.
Scripts run with `set -euo pipefail` (bash) or `$ErrorActionPreference = 'Stop'` (PowerShell).

### `read`
Read a file from a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `path` | string | yes | Absolute path to the file |
| `head` | int | no | Read only first N lines |
| `tail` | int | no | Read only last N lines |

### `write`
Write content to a file on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `path` | string | yes | Absolute path to the file |
| `content` | string | yes | Content to write |
| `append` | bool | no | Append instead of overwrite (default: false) |
| `sudo` | bool | no | Write with sudo (default: false) |

Creates parent directories automatically.

### `transfer`
Transfer a file to/from a host via SCP.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `direction` | string | yes | `"upload"` or `"download"` |
| `local_path` | string | yes | Path on the local (hub) machine |
| `remote_path` | string | yes | Path on the remote host |

### `status`
Check connectivity of all hosts.

Returns structured JSON:
```json
{
  "hosts": {
    "gpu-server": {"status": "connected", "local": true},
    "win-server": {"status": "connected", "local": false},
    "macbook": {"status": "offline", "local": false, "error": "..."}
  },
  "available": 2,
  "total": 3
}
```

Status values: `"connected"`, `"reconnected"`, `"offline"`.

### `reconnect_host`
Reconnect to a host by tearing down the ControlMaster socket and warming up a fresh connection.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |

Use when a host shows as disconnected or commands fail with transport errors. For local hosts, returns immediately (no SSH needed).

### `list_ssh_hosts`
List all hosts defined in `~/.ssh/config`.

No parameters. Read-only — does not modify any configuration.

Returns JSON array:
```json
[
  {"alias": "win-server", "hostname": "win-server.home", "port": 22, "user": "user", "in_fleet": true},
  {"alias": "myserver", "hostname": "10.0.0.5", "port": 22, "user": "", "in_fleet": false}
]
```

Use for discovering available SSH hosts before adding them to the fleet.

### `add_host`
Add a new host to the fleet by writing to `hosts.yaml` and hot-reloading.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Fleet name for the host (e.g. "win-server") |
| `alias` | string | yes | SSH alias from `~/.ssh/config` |
| `description` | string | no | Human-readable description |
| `remote_cli` | string | no | Default agent CLI: `"codex"`, `"gemini"`, or `"claude"` (default: `"codex"`) |
| `is_local` | bool | no | Mark as local hub host (default: false) |

**Requires user approval.** The alias must exist in `~/.ssh/config` (unless `is_local=true`). No password or key parameters — authentication is handled by SSH config and SSH agent.

## Orchestra Tools

### `codex`
Dispatch task to Codex CLI.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `prompt` | string | yes | Task prompt for Codex |
| `working_dir` | string | no | Repository path (default: MAESTRO_DEFAULT_REPO) |
| `model` | string | no | Model override |
| `reasoning_effort` | string | no | Reasoning effort level (default: "xhigh") |

Returns task result inline if completed within block_timeout, otherwise returns `{"auto_promoted": true, "task_id": "..."}`. Use `poll` to check status.

### `gemini`
Dispatch task to Gemini CLI.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `prompt` | string | yes | Task prompt for Gemini |
| `context_files` | list[str] | no | Files to include as `@file` references |
| `working_dir` | string | no | Repository path (default: MAESTRO_DEFAULT_REPO) |
| `model` | string | no | Model override |
| `approval_mode` | string | no | `"plan"` (default), `"yolo"`, `"auto_edit"`, or `"default"` |
| `resume` | string | no | Session index or `"latest"` to continue a chat |

**Warning:** Resuming a session re-sends history and costs tokens for all previous turns.

### `gemini_sessions`
List previous Gemini CLI sessions on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | no | Host to check (default: local host) |

### `claude`
Dispatch task to Claude Code CLI.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name |
| `prompt` | string | yes | Task prompt for Claude |
| `working_dir` | string | no | Repository path (default: MAESTRO_DEFAULT_REPO) |
| `allowed_tools` | string | no | Comma-separated tool list (default: "Edit,Write,Bash(git:*),Read") |

Runs with `--permission-mode bypassPermissions`.

### `poll`
Check task status or retrieve result.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | string | yes | Task ID from a dispatch/auto-promote response |
| `wait` | int | no | Polling mode selector (default: 0) |

**`wait=0` (default):** Returns immediate status. Subject to per-client cooldown (remote: 10s, local: 2s, lan: 5s). Returns task result if complete.

**`wait>0`:** Returns the HTTP endpoint URL and curl pattern instead of blocking. This is the **BUG-0001 safe path** — actual result retrieval happens via `bash_tool` + `curl` through a separate HTTP request-response cycle, immune to MCP SSE session multiplexing issues.

Example response for `wait>0`:
```json
{
  "status": "use_http_endpoint",
  "task_id": "abc123",
  "endpoint": "/tasks/abc123/result",
  "method": "GET",
  "auth": "Bearer <relay_key> (call prepare_relay first)",
  "hint": "Use bash_tool with curl loop for safe polling..."
}
```

### `read_output`
Read full or partial output from a previous agent run.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | yes | Path to the output file (from task result) |
| `start_line` | int | no | Line offset (default: 0) |
| `max_lines` | int | no | Max lines to return (default: 200) |

Only reads files within the orchestra output directory.

### `agent_status`
Check Codex/Gemini CLI availability on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | no | Host to check (default: local host) |

Returns CLI version info and recent output files.

## Auto-Promote Behavior

All execution tools use adaptive blocking based on client classification:

| Client | Agent block_timeout | Exec block_timeout | Poll cooldown |
|--------|--------------------|--------------------|---------------|
| remote | 0s (immediate dispatch) | 5s | 10s |
| local | 30s | 60s | 2s |
| lan | 10s | 20s | 5s |

Client classification:
- **remote** — requests with `CF-Ray` header (Cloudflare tunnel)
- **local** — requests from `127.0.0.1`, `::1`, or `localhost`
- **lan** — requests from `198.51.100.*` subnet

## Observe/Steer Monitoring Guidance (ADR-0008)

`observe` and `steer` are retained for occasional, ad-hoc inspection and
interactive experimentation, but they are not reliable as tight monitoring loops
for production workflows under `remote` transport conditions. Keep loops short or
replace them with log-driven checks.

- Service workflow pattern:
  `service(..., capture=True)` -> `run(host, "tail -50 /path/to/output")`
- Agent workflow pattern:
  `dispatch(...)` -> `tasks(status="running")` -> `read_output(file_path)`

Interactive mode (`mode="interactive"`) remains available but is considered an
experimental conductor path until transport reliability improves.


## HTTP Endpoints (non-MCP)

### `GET /tasks/{task_id}/result`

Retrieve task result via HTTP. Designed for zero-token-cost wait loops using `bash_tool` + curl.

**Auth:** `Authorization: Bearer <daily-HMAC-token>` (same as transfer relay)

| HTTP Status | Meaning |
|---|---|
| 200 | Task complete — body contains the full result JSON |
| 202 | Task still running — body has `task_id`, `status`, `elapsed_seconds` |
| 401 | Missing or invalid Bearer token |
| 404 | Unknown task_id or already evicted |

**Preferred workflow for remote clients (Claude.ai):**

```bash
TOKEN=$(python3 -c "import hmac,hashlib,time; ...")
TASK_ID="<from dispatch response>"

for i in $(seq 1 40); do
  HTTP_CODE=$(curl -s -o /tmp/result.json -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "https://maestro.yourdomain.dev/tasks/$TASK_ID/result")
  [ "$HTTP_CODE" = "200" ] && { cat /tmp/result.json; exit 0; }
  sleep 15
done
```

This costs 2 tool calls total (dispatch + bash wait) regardless of task duration, vs. 6-18 MCP poll calls.

### `POST /transfer/push`

Push a file to a fleet host. See transfer relay documentation.

### `GET /transfer/pull`

Pull a file from a fleet host. See transfer relay documentation.
