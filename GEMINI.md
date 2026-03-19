# Maestro MCP — Gemini CLI Guide

Maestro integrates with Gemini CLI to provide fleet management and agent
orchestration from within a Gemini chat session.

---

## Setup

### 1. Register Maestro as an MCP server

```bash
gemini mcp add maestro \
  /path/to/maestro-mcp/.venv/bin/python \
  /path/to/maestro-mcp/server.py \
  --transport stdio
```

Verify it's registered:

```bash
gemini mcp list
```

Alternatively, the repo ships a `.gemini/settings.json` that registers Maestro
automatically when Gemini CLI is run from the repo directory. Check the path
inside it matches your local install.

### 2. Use Maestro tools from a session

MCP tools are not CLI subcommands — they are only accessible from within a
Gemini chat session (interactive or headless). There is no `gemini mcp call`
syntax.

**Interactive session:**
```bash
gemini
# Then in the session:
# > use maestro to check fleet status
# > run `nvidia-smi` on eden via maestro
```

**Headless (non-interactive):**
```bash
gemini -p "Use maestro to check fleet status and report which hosts are down."
```

---

## Core Fleet Workflows

All examples below are headless. The same prompts work interactively.

### Check fleet status
```bash
gemini -p "Call the maestro status tool and summarise the result."
```

### Execute a command on a host
```bash
gemini -p "Use maestro exec to run 'nvidia-smi' on host eden and show the output."
```

### Read a file (surgical)
```bash
gemini -p "Use maestro read to get the last 50 lines of /var/log/syslog on apollyon."
```

### Transfer a file
```bash
gemini -p "Use maestro transfer to upload ./src/main.py to ~/workspace/main.py on judas."
```

### Discover SSH hosts
```bash
gemini -p "Use maestro list_ssh_hosts to show available SSH hosts and which are already in the fleet."
```

### Reconnect a host
```bash
gemini -p "Use maestro reconnect_host to reset the SSH connection to eden."
```

---

## Agent Orchestra

Maestro can dispatch Gemini CLI tasks as async background processes via the
`gemini` tool. This is Gemini dispatching *itself* — useful for long-running
agentic tasks you want to run in the background while the orchestrating session
stays responsive.

### Dispatch a task
```bash
gemini --approval-mode yolo -p "
Use maestro to dispatch a gemini task on apollyon:
  prompt: 'Refactor the authentication logic in maestro_oauth.py'
  approval_mode: yolo
  working_dir: /home/rmstxrx/Development/maestro-mcp
Then poll until complete and summarise the changes.
"
```

**Key parameters for the `gemini` tool:**

| Parameter | Values | Notes |
|-----------|--------|-------|
| `approval_mode` | `plan`, `yolo`, `auto_edit`, `default` | `plan` = read-only; `yolo` = auto-approve all |
| `resume` | `"latest"` or index number | Continues a previous session |
| `context_files` | list of paths | Included as `@file` references |

> **Warning:** `resume` re-sends the entire session history as input tokens.
> You pay for all previous turns on every resumed call.

### List previous sessions on a host
```bash
gemini -p "Use the maestro gemini_sessions tool on host apollyon to list available sessions."
```

### Poll a dispatched task

For immediate status:
```bash
gemini -p "Use maestro poll with task_id '<id>' and report the result."
```

For long-running tasks, prefer the HTTP endpoint via bash (immune to BUG-0001):
```bash
gemini --approval-mode yolo -p "
Call maestro prepare_relay, then use bash to poll the task result:
  for i in \$(seq 1 40); do
    HTTP_CODE=\$(curl -s -o /tmp/result.json -w '%{http_code}' -H 'Authorization: Bearer \$RELAY_KEY' 'https://maestro.rmstxrx.dev/tasks/TASK_ID/result')
    [ \"\$HTTP_CODE\" = \"200\" ] && cat /tmp/result.json && break
    sleep 15
  done
"
```

---

## Best Practices

- **Token budget:** Every maestro tool response enters Gemini's context window.
  Use `exec` with `grep`/`head`/`tail` instead of `read` on large files.
- **Use `prepare_relay` + curl for task results** — zero context cost.
- **Headless for scripting:** Use `gemini -p "..."` for automation; interactive
  mode for exploratory work.
- **Sensitive data:** Never commit `hosts.yaml` or `.env`. They are gitignored
  by default.

---

## Tool Quick Reference

| Tool | Purpose |
|------|---------|
| `exec` | Run a command on a host |
| `script` | Run a multi-line script |
| `read` / `write` | File operations |
| `transfer` | SCP file transfer |
| `status` | Fleet connectivity check |
| `reconnect_host` | Reset SSH connection to a host |
| `list_ssh_hosts` | Discover hosts from ~/.ssh/config |
| `add_host` | Add host to fleet (requires approval) |
| `codex` / `gemini` / `claude` | Dispatch to agent CLI |
| `poll` | Check task status |
| `read_output` | Read agent output file |
| `prepare_relay` | Get ephemeral relay token |
| `agent_status` | Check CLI availability |
