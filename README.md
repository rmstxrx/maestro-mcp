# 🎼 Maestro MCP

> *An Opus is a piece that deserves to be held by an Orchestra, conducted by a proper Maestro.*

**Maestro** is an MCP server that turns a heterogeneous machine fleet into a unified workspace for AI agents. SSH into any host, run commands across platforms, transfer files, and dispatch coding agents — all through a single orchestration layer.

Built for developers/power users who work across multiple machines and want their AI assistant to do the same.

---

## Why Maestro?

Most MCP SSH servers connect to **one host**. You configure a hostname, a key, and you're in.

But that's not how real setups work. You have a GPU box running Linux, a MacBook for travel, a Windows workstation with WSL — each with different shells, different paths, different capabilities. You don't just need SSH. You need a **conductor** that understands the whole orchestra.

Maestro gives your AI agent the same mental model you have: named hosts, persistent connections, cross-platform awareness, and the ability to dispatch long-running tasks to coding agents while continuing the conversation.

---

## Features

- **Named hosts** with per-host shell awareness (Bash, PowerShell, WSL)
- **SSH ControlMaster** lifecycle — persistent multiplexed connections with auto-reconnect and exponential backoff
- **Local routing** — the hub machine bypasses SSH entirely for zero-overhead local execution
- **Dual-mode execution** — inline commands (20s, synchronous) for quick ops, staged scripts (async, tmux) for long-running tasks
- **Direct file I/O** — `read` and `write` small files (≤4 KB) over SSH with hard timeouts
- **Transfer relay** — push/pull larger files via HTTP endpoints with Bearer token auth
- **Fleet status** — one-command health check across all hosts with auto-reconnection
- **Agent orchestra** — dispatch [Codex CLI](https://github.com/openai/codex), [Gemini CLI](https://github.com/google-gemini/gemini-cli), or [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview) as async background tasks with ledger tracking, live observation, and steering
- **Task ledger** — persistent task history surviving restarts, with automatic 30-day pruning
- **Remote access** *(optional)* — OAuth 2.1 with PIN-gated consent for exposing Maestro over HTTP (e.g., from Claude.ai via Cloudflare Tunnel)

---

## Architecture

Maestro runs on one **hub machine** — the one with SSH access to all others. Star topology: every host is one hop from the hub. The hub itself is marked `is_local: true` and executes locally with no SSH overhead.

Dispatched agents (Codex, Gemini, Claude Code) run in **hub-local tmux windows** that SSH into the target host. The orchestrator can observe their output, send keystrokes, and stop them — all without entering the agent's context.

```
              AI Agent (Claude.ai / Claude Code / Codex CLI)
                         │
                    MCP protocol
                    (stdio or HTTP)
                         │
                  ┌──────┴──────┐
                  │   Maestro   │  ← hub machine (is_local: true)
                  │  ┌────────┐ │
                  │  │ ledger │ │     persistent task history
                  │  └────────┘ │
                  │  ┌────────┐ │
                  │  │  tmux  │ │     agent dispatch windows
                  │  └────────┘ │
                  └──┬───┬───┬──┘
                     │   │   │
              SSH ControlMaster pool
                     │   │   │
                ┌────┘   │   └────┐
                ▼        ▼        ▼
            linux-box  win-pc   macbook
            (bash)     (pwsh)   (bash)
                         │
                         └─► WSL (ProxyCommand)
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- SSH configured with `~/.ssh/config` entries for your remote hosts (ControlMaster recommended)
- [MCP SDK](https://github.com/modelcontextprotocol/python-sdk) (`pip install "mcp[cli]"`)

### 1. Clone and install

```bash
git clone https://github.com/rmstxrx/maestro-mcp.git
cd maestro-mcp

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Define your fleet

Copy the example config and edit it. **CRITICAL:** `hosts.yaml` and `.env` contain sensitive data (IPs, hostnames, PIN hashes, and tokens). They are git-ignored by default. **Never commit these files or hardcode sensitive topology details if you plan to push your fork to a public repository.**

```bash
cp hosts.example.yaml hosts.yaml
```

```yaml
# hosts.yaml — define your machine fleet
hosts:
  workstation:
    alias: ssh-workstation        # must match a Host entry in ~/.ssh/config
    description: "Main dev box, Arch Linux"
    is_local: true                # hub machine — no SSH, direct execution

  gpu-box:
    alias: ssh-gpu
    description: "Training rig, Ubuntu 24.04"
    # shell: bash (default)

  macbook:
    alias: ssh-macbook
    description: "MacBook Pro, on the go"

  windows-pc:
    alias: ssh-winpc
    description: "Windows 11, PowerShell"
    shell: powershell

  windows-wsl:
    alias: ssh-winpc-wsl
    description: "WSL2 on windows-pc (ProxyCommand)"
    # shell: bash (default)
```

### 3. Set up authentication

```bash
# Generate a PIN hash for the OAuth consent gate
python -c "import hashlib; pin = input('Choose a PIN: '); print(hashlib.sha256(pin.encode()).hexdigest())"
```

Create your `.env` file:
```bash
cp .env.example .env
# Edit .env and paste your PIN hash
```

```env
# .env
MAESTRO_AUTHORIZE_PIN_HASH="your_sha256_hash_here"
SSH_TIMEOUT=300
MAESTRO_ISSUER_URL=https://your-domain.example.com  # Required for HTTP transport
# MAESTRO_TRANSFER_ALLOWED_DIRS="~/,/tmp"           # Paths the relay can write to
# MAESTRO_DEFAULT_REPO=~/workspace                   # Default working dir for agents
```

### 4. Run

```bash
# Local MCP client (stdio transport, for Codex CLI / Claude Code / Claude Desktop)
.venv/bin/python server.py --transport stdio

# Remote/cloud access (HTTP transport, for Claude.ai via tunnel)
.venv/bin/python server.py --transport streamable-http --port 8222 --host 127.0.0.1
```

### 5. Connect your AI client

**Claude Code:**
```bash
claude mcp add maestro -- /path/to/maestro-mcp/.venv/bin/python /path/to/maestro-mcp/server.py --transport stdio
```

**Codex CLI:**
```bash
codex mcp add maestro -- /path/to/maestro-mcp/.venv/bin/python /path/to/maestro-mcp/server.py --transport stdio
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "maestro": {
      "command": "/path/to/maestro-mcp/.venv/bin/python",
      "args": ["/path/to/maestro-mcp/server.py", "--transport", "stdio"]
    }
  }
}
```

**Claude.ai** (via Cloudflare Tunnel or similar):
Point the MCP connector to your tunnel URL. OAuth consent is handled automatically for Claude.ai clients.

---

## Tools Reference

### Fleet Tools

| Tool | Description |
|------|-------------|
| `exec` | Execute on any host. **Inline mode** (`command=`): synchronous SSH, 20s hard timeout, returns stdout/stderr directly. **Staged mode** (`task_id=`): runs a pre-staged script in tmux, returns task_id for polling. |
| `read` | Read a file from any host (≤4 KB, 10s timeout). Returns content directly. |
| `write` | Write a file to any host (≤4 KB, 10s timeout). Content piped via stdin. |
| `status` | Fleet health check with auto-reconnect. Optional `agents=True` to probe CLI availability. |
| `service` | Start a long-running process (vLLM, Jupyter, etc.). No hard ceiling — runs until stopped. |
| `observe` | Capture live output from a running task's tmux pane (~50 lines). |
| `steer` | Send keystrokes to a running task (approval prompts, Ctrl+C, input). |
| `stop` | Kill a running task's tmux window. Updates the ledger. |

### Agent Orchestra

| Tool | Description |
|------|-------------|
| `dispatch` | Dispatch a coding agent (Codex, Gemini, or Claude Code) to any host. Runs in a hub-local tmux window. Returns task_id for tracking. |
| `poll` | Check status of a dispatched task. Shows elapsed time and overtime flag. |
| `tasks` | List recent tasks from the persistent ledger. Filter by status, agent, host, or task type. |
| `prepare_relay` | Get an ephemeral Bearer token (1h TTL) for the HTTP file transfer relay. |
| `gemini_sessions` | List previous Gemini CLI sessions on a host. |

### Execution Tiers

| Tier | Tool | Timeout | Use case |
|------|------|---------|----------|
| 1 | `read` / `write` | 10s | File I/O under 4 KB |
| 2 | `exec` inline | 20s | Quick commands, no reasoning needed |
| 3 | `exec` staged | 6h | Long scripts, builds, deployments |
| 4 | `dispatch` | 6h | Agent tasks requiring reasoning |

---

## File Transfer

Maestro provides two mechanisms for moving files:

**Direct I/O** (`read`/`write`) — for small files (≤4 KB). Uses SSH, returns content in the tool response. Fast, simple, one tool call.

**Transfer relay** (`prepare_relay` + HTTP push/pull) — for larger files. The relay endpoints accept multipart uploads and stream downloads, authenticated with ephemeral Bearer tokens. This keeps large file content out of the LLM context window.

```bash
# Get a relay token (via MCP tool)
# prepare_relay → {"value": "abc123...", "ttl_seconds": 3600}

# Push a file to a host
curl -H "Authorization: Bearer abc123..." \
  -F "file=@local_file.py" \
  "https://your-maestro/transfer/push?host=gpu-box&remote_path=/home/user/file.py"

# Pull a file from a host
curl -H "Authorization: Bearer abc123..." \
  -o local_file.py \
  "https://your-maestro/transfer/pull?host=gpu-box&remote_path=/home/user/file.py"
```

---

## SSH Configuration Tips

Maestro relies on your existing `~/.ssh/config`. Here's a recommended setup for fleet usage:

```ssh-config
# Global: enable ControlMaster for all hosts
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
    ServerAliveInterval 30
    ServerAliveCountMax 3

# Direct hosts
Host ssh-gpu
    HostName 192.168.1.100
    User dev

Host ssh-macbook
    HostName macbook.local
    User user

# Windows host (PowerShell over OpenSSH)
Host ssh-winpc
    HostName 192.168.1.200
    User admin

# WSL via ProxyCommand through Windows host
Host ssh-winpc-wsl
    User user
    ProxyCommand ssh ssh-winpc "wsl -d Ubuntu -e nc localhost 22"
```

```bash
# Don't forget to create the sockets directory
mkdir -p ~/.ssh/sockets
```

---

## Deployment

### Docker Compose (recommended for HTTP transport)

```yaml
services:
  maestro:
    build: .
    container_name: maestro
    restart: unless-stopped
    ports:
      - "8222:8222"
    env_file:
      - ./config/.env
    volumes:
      - ./config/ssh:/mnt/ssh:ro          # SSH keys and config
      - ./config/hosts.yaml:/app/hosts.yaml:ro
      - ./state:/root/.maestro            # Task ledger, OAuth state
      # For is_local hub: mount host paths the relay needs to access
      # - /home/user/workspace:/home/user/workspace
      # - /tmp/maestro:/tmp/maestro
```

### Exposing via Cloudflare Tunnel

If you want Claude.ai to reach your Maestro instance:

```bash
cloudflared tunnel --url http://localhost:8222
```

Or as a persistent named tunnel — see [Cloudflare's documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/).

### As a systemd service (stdio or HTTP)

```ini
# /etc/systemd/system/maestro.service
[Unit]
Description=Maestro MCP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/maestro-mcp
EnvironmentFile=/path/to/maestro-mcp/.env
ExecStart=/path/to/maestro-mcp/.venv/bin/python server.py --transport streamable-http --port 8222
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Project Structure

```
maestro-mcp/
├── server.py                  # Entry point — FastMCP wiring, routes, middleware
├── maestro/
│   ├── tools/
│   │   ├── fleet.py           # Fleet tools: exec, read, write, status, observe, steer, stop, service
│   │   └── orchestra.py       # Agent dispatch: codex, gemini, claude, poll, tasks, prepare_relay
│   ├── client.py              # Client classification (remote/local/LAN/stdio)
│   ├── config.py              # MaestroConfig from environment
│   ├── hosts.py               # Host registry, status tracking, command wrapping
│   ├── mux.py                 # Hub-local tmux multiplexer for agent dispatch
│   ├── relay.py               # HTTP file transfer relay (push/pull/task results)
│   └── transport.py           # SSH execution layer (async_run, retries, connection lifecycle)
├── maestro_oauth.py           # OAuth 2.1 provider with PIN-gated consent
├── oauth_rewrite.py           # URL rewrite middleware for multi-origin OAuth
├── hosts.yaml                 # Your fleet definition (git-ignored)
├── hosts.example.yaml         # Example fleet config
├── .env                       # Secrets — PIN hash, tokens (git-ignored)
├── .env.example               # Template for .env
├── docker-compose.yml         # Docker deployment config
├── Dockerfile                 # Container build
├── requirements.txt           # Python dependencies
└── LICENSE                    # Apache 2.0
```

---

## Gotchas

- **Claude.ai tool filtering:** Claude.ai's MCP connector can silently filter tools whose name or description suggests credential generation. If a tool disappears from discovery, inspect the tool name and description for terms like `token`, `secret`, `key`, `auth`, `bearer`, or `credential`, then rename and sanitize. The filtering is intent-based, not pure keyword matching.

- **Tool definition caching:** After rebuilding the Maestro container, you must fully disconnect and reconnect the MCP connector in Claude.ai settings. Tool definitions are cached at the OAuth session level.

- **Context budget:** Tool responses consume LLM context. Use `exec` with `grep`, `head`, `tail`, `jq` for surgical reads. Use `read` only for files under 4 KB. For larger files, use the transfer relay — the response is just `{"status": "ok"}`, near-zero context cost.

---

## Origin

Maestro was born from necessity. I work across multiple machines — a Linux box for inference, a Windows PC for training, and a MacBook for when I'm away from the desk. I got tired of my AI assistant only seeing one machine at a time while I had to manually bridge the gaps.

What started as a simple SSH relay grew into a full orchestration layer: persistent connections, cross-platform shell awareness, agent dispatch, and eventually OAuth for remote access from Claude.ai. The name came naturally — if the models are the instruments, someone needs to conduct.

---

## License

[Apache 2.0](LICENSE) — use it freely, contribute fearlessly, and don't weaponize patents.

---

## Contributing

Contributions are welcome. If you're building something with Maestro, I'd love to hear about it.

For bug reports and feature requests, open an issue. For code contributions, please open a PR with a clear description of what changed and why.
