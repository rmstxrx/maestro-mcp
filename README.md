# 🎼 Maestro MCP

> *An Opus is a piece that deserves to be held by an Orchestra, conducted by a proper Maestro.*

**Maestro** is an MCP server that turns a heterogeneous machine fleet into a unified workspace for AI agents. SSH into any host, run commands across platforms, transfer files, and dispatch coding agents — all through a single orchestration layer.

Built for developers/power users in general who work across multiple machines and want their AI assistant to do the same.

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
- **Cross-platform commands** — `exec` adapts to each host's shell automatically
- **Multi-line scripts** — `script` pipes scripts via `bash -s` or PowerShell stdin
- **File operations** — `read`, `write`, and `transfer` (SCP) across any host
- **Fleet status** — one-command health check across all hosts with auto-reconnection
- **Agent orchestra** *(optional)* — dispatch [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview), [Codex CLI](https://github.com/openai/codex), [Gemini CLI](https://github.com/google-gemini/gemini-cli), or [OpenCode CLI](https://opencode.ai) as async background tasks with budget caps, output pagination, and polling
- **Remote access** *(optional)* — OAuth 2.1 with PIN-gated consent for exposing Maestro over HTTP (e.g., from Claude.ai via Cloudflare Tunnel). Not needed for stdio usage with Codex CLI, Claude Code, or Claude Desktop

---

## Architecture

Maestro runs on one **hub machine** — the one with SSH access to all others. Star topology: every host is one hop from the hub. The hub itself executes locally, no SSH overhead.

```
                  AI Agent (MCP client)
                         │
                    MCP protocol
                         │
                  ┌──────┴──────┐
                  │   Maestro   │  ← hub machine (is_local: true)
                  └──┬───┬───┬──┘
                     │   │   │
              SSH ControlMaster pool
                     │   │   │
                ┌────┘   │   └────┐
                ▼        ▼        ▼
            linux-box  win-pc   macbook
            (bash)     (pwsh)   (bash)
                         │
                         └─► WSL (ProxyJump)
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
    description: "WSL2 on windows-pc (ProxyJump)"
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
# MAESTRO_DEFAULT_REPO=~/workspace                  # Default working dir for agent tools
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

### Fleet Core

| Tool | Description |
|------|-------------|
| `exec` | Execute a shell command on any host |
| `script` | Run a multi-line script (piped via `bash -s` or PowerShell) |
| `read` | Read a text file (with optional `head`/`tail` line limits) |
| `write` | Write or append to a file (creates parent dirs automatically) |
| `transfer` | SCP a file to or from a remote host |
| `status` | Health check all hosts, auto-reconnect stale connections |

### Agent Orchestra

| Tool | Description |
|------|-------------|
| `claude` | Run Claude Code with inline-or-background auto-promote |
| `codex` | Run OpenAI Codex CLI with inline-or-background auto-promote |
| `gemini` | Run Gemini CLI with `approval_mode` and `resume` support |
| `opencode` | Run OpenCode CLI with `session_id`, model selection, and JSON format |
| `opencode_sessions` | List previous OpenCode CLI sessions on a host |
| `gemini_sessions` | List previous Gemini CLI sessions on a host |
| `install_agent` | Install a CLI agent (opencode/codex/gemini/claude) on a remote host |
| `poll` | Check status of an auto-promoted task |
| `read_output` | Read full or partial output from a completed task |
| `agent_status` | Check which CLI agents are available on a host |

> **Why did Gemini change?** The `mode` parameter was replaced with `approval_mode` to align directly with Gemini CLI flags (`plan`, `yolo`, `auto_edit`). Added `resume` support for continuing sessions and `gemini_sessions` for easier session management.

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

# WSL via ProxyJump through Windows host
Host ssh-winpc-wsl
    HostName localhost
    Port 2222
    User user
    ProxyJump ssh-winpc
```

```bash
# Don't forget to create the sockets directory
mkdir -p ~/.ssh/sockets
```

---

## Deployment

### As a systemd service

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
ExecStart=/path/to/maestro-mcp/.venv/bin/python server.py --transport streamable-http --port 8222 --host 127.0.0.1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Exposing via Cloudflare Tunnel

If you want Claude.ai to reach your Maestro instance:

```bash
cloudflared tunnel --url http://localhost:8222
```

Or as a persistent named tunnel — see [Cloudflare's documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/).

---

## Project Structure

```
maestro-mcp/
├── server.py                  # Main MCP server — fleet tools + agent orchestra
├── maestro_oauth.py           # OAuth 2.1 provider with PIN-gated consent
├── hosts.yaml                 # Your fleet definition (git-ignored)
├── hosts.example.yaml         # Example fleet config
├── .env                       # Secrets — PIN hash, tokens (git-ignored)
├── .env.example               # Template for .env
├── pyproject.toml             # Project metadata
├── requirements.txt           # Python dependencies
├── maestro.service            # systemd unit file (example)
├── cloudflared-maestro.service # Cloudflare Tunnel unit (example)
└── LICENSE                    # Apache 2.0
```

---

## Context Budget Awareness

A key design insight from daily usage with Claude: **tool responses consume LLM context**. Every byte returned by `read` enters the conversation permanently. For large files, this causes context exhaustion.

Best practice:
- Use `exec` with `grep`, `head`, `tail`, `sed`, `awk`, `jq` for surgical reads
- Use `transfer` to move files to the hub disk (response is just `[OK]`, ≈0 context cost)
- Use `read` with `head`/`tail` parameters for bounded reads
- Reserve `read` (no limits) for files under ~100 lines

The agent orchestra tools follow the same principle: full output is saved to disk, and only a truncated summary enters the conversation. Use `read_output` with line ranges for targeted inspection.

---

## Origin

Maestro was born from necessity. I work across three machines — a Linux box for inference, a Windows PC for training, and a MacBook for when I'm away from the desk. I got tired of my AI assistant only seeing one machine at a time while I had to manually bridge the gaps.

What started as a simple SSH relay grew into a full orchestration layer: persistent connections, cross-platform shell awareness, agent dispatch, and eventually OAuth for remote access from Claude.ai. The name came naturally — if the models are the instruments, someone needs to conduct.

---

## License

[Apache 2.0](LICENSE) — use it freely, contribute fearlessly, and don't weaponize patents.

---

## Contributing

Contributions are welcome. If you're building something with Maestro, I'd love to hear about it.

For bug reports and feature requests, open an issue. For code contributions, please open a PR with a clear description of what changed and why.
