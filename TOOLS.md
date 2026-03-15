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
    "apollyon": {"status": "connected", "local": true},
    "eden": {"status": "connected", "local": false},
    "judas": {"status": "offline", "local": false, "error": "..."}
  },
  "available": 2,
  "total": 3
}
```

Status values: `"connected"`, `"reconnected"`, `"offline"`.

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

### `opencode`
Dispatch task to OpenCode CLI.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name from fleet topology |
| `prompt` | string | yes | Task prompt for OpenCode |
| `working_dir` | string | no | Repository path (default: MAESTRO_DEFAULT_REPO) |
| `model` | string | no | Model override (provider/model format) |
| `session_id` | string | no | Session ID to continue existing session |

Returns task result inline if completed within block_timeout, otherwise returns `{"auto_promoted": true, "task_id": "..."}`. Use `poll` to check status.

### `opencode_sessions`
List previous OpenCode CLI sessions on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | no | Host to check (default: local host) |

### `poll`
Check task status or retrieve result.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | string | yes | Task ID from a dispatch/auto-promote response |

Returns the task result if complete, or status info if still running.
Subject to per-client poll cooldown (remote: 10s, local: 2s, lan: 5s).

### `read_output`
Read full or partial output from a previous agent run.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | yes | Path to the output file (from task result) |
| `start_line` | int | no | Line offset (default: 0) |
| `max_lines` | int | no | Max lines to return (default: 200) |

Only reads files within the orchestra output directory.

### `agent_status`
Check Codex/Gemini/OpenCode/Claude CLI availability on a host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | no | Host to check (default: local host) |

Returns CLI version info and recent output files.

### `install_agent`
Install a CLI agent (opencode/codex/gemini/claude) on a remote host.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | yes | Target host name from fleet topology |
| `agent` | string | yes | Agent to install: `opencode`, `codex`, `gemini`, or `claude` |
| `force` | bool | no | Skip confirmation and install anyway (default: false) |

Checks system requirements before installation:
- Disk space (needs ~500MB)
- Architecture (x86_64 or arm64)
- Required tools (curl for opencode, npm for others)

Returns installation result with status and version info.

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
- **lan** — requests from `10.42.69.*` subnet
