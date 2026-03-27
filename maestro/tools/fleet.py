"""Fleet MCP tool functions."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import shlex
from pathlib import Path
from typing import Any

from maestro.client import get_client_context
from maestro.config import MaestroConfig
from maestro.hosts import (
    HOSTS,
    HostConfig,
    HostShell,
    HostStatus,
    _local_host_name,
    _ps_quote,
    _resolve_host,
    _update_host_status,
    _wrap_command,
)
from maestro.local import (
    _local_copy,
    _local_read_file,
    _local_write_file,
)
from maestro.mux import (
    # Legacy (remote-tmux) — used by exec/script during transition
    mux_capture,
    mux_kill_window,
    mux_list_windows,
    mux_run,
    mux_send_keys,
    mux_spawn,
    # New (Cellar-local tmux) — used by run
    capture_pane,
    cleanup_task_files,
    create_task_window,
    get_output_path,
    kill_window,
    list_windows,
    send_keys,
    wait_for_completion,
)
from maestro.tools.orchestra import (
    _auto_promote,
    _orchestra_output_dir,
    _orchestra_run_cli,
)
from maestro.transport import (
    _check_control_master,
    _scp_run,
    _ssh_run,
    _structured_error,
    _teardown_connection,
    _warmup_connection,
)

logger = logging.getLogger("maestro")

_AGENT_CLI_PATTERNS = re.compile(
    r"^\s*(codex|gemini|claude)\b.*(?:-[pq]|--prompt|--model|--message)(?:\s|=|$)",
    re.IGNORECASE | re.DOTALL,
)
_WINDOW_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")


def _check_local_self_reference(host: str) -> str | None:
    """Block stdio clients from targeting the local host with fleet I/O tools.

    Returns an error JSON string if blocked, None if the command should proceed.
    """
    ctx = get_client_context()
    if not hasattr(ctx, "client_type") or ctx.client_type != "stdio":
        return None
    try:
        cfg = _resolve_host(host)
    except ValueError:
        return None  # let the tool handle the unknown host error
    if not cfg.is_local:
        return None
    return json.dumps({
        "error": "local_self_reference",
        "host": host,
        "blocked": True,
        "message": (
            f"You are running on {host}. Use your native Bash/filesystem "
            f"tools for local commands — they are faster and more capable. "
            f"Maestro fleet tools are for remote hosts only when using stdio transport."
        ),
    })


def _check_agent_dispatch_bypass(command: str) -> str | None:
    """Block raw agent CLI dispatches that should use orchestra tools instead."""
    match = _AGENT_CLI_PATTERNS.search(command)
    if match is None:
        return None
    agent = match.group(1).lower()
    return json.dumps({
        "error": "agent_dispatch_bypass",
        "blocked": True,
        "detected_agent": agent,
        "recommended_tool": agent,
        "message": (
            f"Detected a raw {agent} CLI dispatch with prompt/model flags. "
            f"Use the {agent} dispatch tool instead so Maestro applies the scope prefix, "
            f"records the task in the ledger, and builds the correct CLI arguments."
        ),
    })


def _resolve_mux_host(host: str) -> HostConfig:
    cfg = _resolve_host(host)
    if cfg.shell == HostShell.POWERSHELL:
        raise ValueError("tmux tools do not support PowerShell hosts")
    return cfg


def _validate_window_name(name: str) -> None:
    if not _WINDOW_NAME_PATTERN.fullmatch(name):
        raise ValueError("window name must match [a-zA-Z0-9_-] and be at most 50 characters")


def register_fleet_tools(mcp: object, config: MaestroConfig) -> None:
    """Register fleet tools on the given FastMCP instance."""

    from mcp.server.fastmcp import FastMCP
    assert isinstance(mcp, FastMCP)

    # --- Fleet tools ---

    # --- ADR-0007: Cellar-local execution via run ---

    @mcp.tool()
    async def run(
        host: str,
        command: str,
        cwd: str | None = None,
        sudo: bool = False,
        expected_runtime: int | None = None,
    ) -> str:
        """Execute a command or multi-line script on a host (ADR-0007).

        Single commands and multi-line scripts are handled uniformly —
        Maestro detects multi-line input and pipes via bash -s automatically.
        Every execution is ledger-tracked with output captured to Cellar disk.

        Guards: rejects raw agent CLI invocations (use dispatch instead).
        In stdio mode, rejects commands targeting the local host.

        Timeout: 300s hard ceiling (system policy, not configurable per-call).
        expected_runtime: your estimate in seconds (default 15). Recorded
        verbatim in the ledger. Task flagged as overtime at exactly this value.

        Returns inline result or {auto_promoted: true, task_id} for long tasks.
        Use observe(task_id) for live output, tasks() for status."""
        if block := _check_local_self_reference(host):
            return block
        if block := _check_agent_dispatch_bypass(command):
            return block
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        ctx = get_client_context()
        block_timeout = ctx.profile["block_timeout_exec"]
        is_script = "\n" in command.strip()
        task_id = secrets.token_hex(8)
        ert = expected_runtime if expected_runtime is not None else config.default_expected_runtime_run

        async def _execute() -> str:
            output_file = await create_task_window(
                task_id,
                cfg.alias,
                command,
                tee=True,
                is_script=is_script,
                cwd=cwd,
                sudo=sudo,
                shell=cfg.shell.value,
            )
            rc = await wait_for_completion(task_id, timeout=config.run_ceiling)

            output = ""
            if output_file and output_file.exists():
                raw = output_file.read_text(encoding="utf-8", errors="replace")
                # Truncate for inline response (full output on disk)
                if len(raw) > config.max_inline_output:
                    output = raw[:config.max_inline_output] + "\n... [truncated, use read_output]"
                else:
                    output = raw
            cleanup_task_files(task_id)
            return json.dumps({
                "_host": host,
                "_agent": "run",
                "output": output,
                "return_code": rc,
                "output_file": str(output_file) if output_file else None,
            })

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="run",
            host=host,
            prompt=command[:200],
            client_class=ctx.classification,
            task_id=task_id,
            expected_runtime=ert,
        )


    @mcp.tool()
    async def exec(host: str, command: str, cwd: str | None = None, sudo: bool = False) -> str:
        """Run a shell command on a host. Returns JSON with output.

        Guards: rejects raw agent CLI invocations (use codex/claude/gemini tools instead). In stdio mode, rejects commands targeting the local host (use native Bash).
        Auto-promotes to background if execution exceeds the client's block_timeout_exec (5s remote, 60s local). Check for "auto_promoted" in response.
        Best for: grep, head, ls, git status, nvidia-smi, systemctl. Context cost = stdout size."""
        if block := _check_local_self_reference(host):
            return block
        if block := _check_agent_dispatch_bypass(command):
            return block
        try:
            _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        ctx = get_client_context()
        timeout = config.ssh_timeout
        block_timeout = ctx.profile["block_timeout_exec"]

        async def _execute() -> str:
            cfg = _resolve_host(host)
            if cfg.shell == HostShell.POWERSHELL:
                raw = await _ssh_run(host, [_wrap_command(cfg, command, cwd, sudo)], timeout=timeout)
            elif cfg.is_local:
                parts = []
                if sudo:
                    parts.append("sudo")
                parts.append(command)
                raw = await mux_run(host, " ".join(parts), timeout=timeout, cwd=cwd)
            else:
                raw = await mux_run(host, _wrap_command(cfg, command, cwd, sudo), timeout=timeout)
            return json.dumps({"_host": host, "_agent": "exec", "output": raw})

        return await _auto_promote(
            _execute, block_timeout=block_timeout,
            agent="exec", host=host, prompt=command[:200],
            client_class=ctx.classification,
        )

    @mcp.tool()
    async def script(host: str, script: str, cwd: str | None = None, sudo: bool = False) -> str:
        """Run a multi-line script on a host (piped via bash -s or PowerShell). Same guards and auto-promote as exec.

        Use for multi-step operations with conditionals or loops. Bash scripts get set -euo pipefail prepended automatically."""
        if block := _check_local_self_reference(host):
            return block
        if block := _check_agent_dispatch_bypass(script):
            return block
        try:
            _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        ctx = get_client_context()
        timeout = config.ssh_timeout
        block_timeout = ctx.profile["block_timeout_exec"]

        async def _execute() -> str:
            cfg = _resolve_host(host)
            lines = []
            if cfg.shell == HostShell.POWERSHELL:
                lines.append("$ErrorActionPreference = 'Stop'")
                if cwd:
                    lines.append(f"Set-Location -LiteralPath {_ps_quote(cwd)}")
                lines.append(script)
                stdin_body = "\n".join(lines)
                interpreter = ["powershell", "-Command", "-"]
                raw = await _ssh_run(host, interpreter, timeout=timeout, stdin_data=stdin_body)
            else:
                lines.append("set -euo pipefail")
                if cwd:
                    lines.append(f"cd {shlex.quote(cwd)}")
                lines.append(script)
                stdin_body = "\n".join(lines)
                raw = await mux_run(host, stdin_body, timeout=timeout, sudo=sudo)
            return json.dumps({"_host": host, "_agent": "script", "output": raw})

        return await _auto_promote(
            _execute, block_timeout=block_timeout,
            agent="script", host=host, prompt=script[:200],
            client_class=ctx.classification,
        )

    @mcp.tool()
    async def read(host: str, path: str, head: int | None = None, tail: int | None = None) -> str:
        """Read a file from a host. For large files, prefer exec + grep/head/sed to avoid context bloat."""
        if block := _check_local_self_reference(host):
            return block
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.is_local:
            return _local_read_file(path, head=head, tail=tail)
        if cfg.shell == HostShell.POWERSHELL:
            if head:
                cmd = f"Get-Content -LiteralPath {_ps_quote(path)} -TotalCount {head}"
            elif tail:
                cmd = f"Get-Content -LiteralPath {_ps_quote(path)} -Tail {tail}"
            else:
                cmd = f"Get-Content -LiteralPath {_ps_quote(path)}"
        else:
            if head:
                cmd = f"head -n {head} {shlex.quote(path)}"
            elif tail:
                cmd = f"tail -n {tail} {shlex.quote(path)}"
            else:
                cmd = f"cat {shlex.quote(path)}"
        return await _ssh_run(host, [cmd], timeout=config.ssh_timeout)

    @mcp.tool()
    async def write(host: str, path: str, content: str, append: bool = False, sudo: bool = False) -> str:
        """Write content to a file on a host. Creates parent directories automatically.

        Content transits MCP (context-expensive for large payloads). For files >1KB that don't need inline reasoning, prefer prepare_relay + curl push instead."""
        if block := _check_local_self_reference(host):
            return block
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        timeout = config.ssh_timeout
        if cfg.is_local:
            return _local_write_file(path, content, append=append, sudo=sudo)
        if cfg.shell == HostShell.POWERSHELL:
            if append:
                cmd = f"$input | Out-File -Append -LiteralPath {_ps_quote(path)}"
            else:
                cmd = f"$input | Out-File -LiteralPath {_ps_quote(path)}"
            return await _ssh_run(host, [cmd], timeout=timeout, stdin_data=content)
        else:
            parent = os.path.dirname(path)
            quoted = shlex.quote(path)
            tee_flag = "-a" if append else ""
            if sudo:
                mkdir_part = f"sudo mkdir -p {shlex.quote(parent)} && " if parent else ""
                cmd = f"{mkdir_part}sudo tee {tee_flag} {quoted} > /dev/null"
            else:
                mkdir_part = f"mkdir -p {shlex.quote(parent)} && " if parent else ""
                cmd = f"{mkdir_part}tee {tee_flag} {quoted} > /dev/null"
            return await _ssh_run(host, [cmd], timeout=timeout, stdin_data=content)

    @mcp.tool()
    async def transfer(host: str, direction: str, local_path: str, remote_path: str) -> str:
        """Transfer a file to/from a host via SCP. direction: "upload" or "download". For large files, prefer prepare_relay + curl push/pull (zero context cost)."""
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if direction == "upload":
            if cfg.is_local:
                return _local_copy(local_path, remote_path, upload=True)
            return await _scp_run(host, local_path, remote_path, upload=True)
        elif direction == "download":
            if cfg.is_local:
                return _local_copy(remote_path, local_path, upload=False)
            return await _scp_run(host, remote_path, local_path, upload=False)
        else:
            return json.dumps({"error": f"Invalid direction '{direction}'. Use 'upload' or 'download'."})

    @mcp.tool()
    async def status() -> str:
        """Check connectivity of all hosts. Returns structured JSON."""

        async def _check_one(name: str, cfg: HostConfig) -> dict:
            if cfg.is_local:
                await _update_host_status(name, HostStatus.CONNECTED)
                return {"status": "connected", "local": True}
            alive = await _check_control_master(cfg.alias)
            if alive:
                await _update_host_status(name, HostStatus.CONNECTED)
                return {"status": "connected", "local": False}
            if await _warmup_connection(cfg.alias):
                await _update_host_status(name, HostStatus.CONNECTED)
                return {"status": "reconnected", "local": False}
            await _update_host_status(name, HostStatus.DISCONNECTED)
            result: dict = {"status": "offline", "local": False}
            if cfg.last_error:
                result["error"] = cfg.last_error
            return result

        results = await asyncio.gather(
            *[_check_one(name, cfg) for name, cfg in HOSTS.items()]
        )
        hosts_status = dict(zip(HOSTS.keys(), results))
        connected = sum(1 for r in results if r["status"] in ("connected", "reconnected"))
        return json.dumps({
            "hosts": hosts_status,
            "available": connected,
            "total": len(HOSTS),
        })

    @mcp.tool()
    async def reconnect_host(host: str) -> str:
        """Reconnect to a host by tearing down the ControlMaster socket and warming up a fresh connection. Use when a host shows as disconnected or commands fail with transport errors."""
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.is_local:
            return json.dumps({"host": host, "status": "local", "message": "Local host needs no reconnection"})

        await _teardown_connection(cfg.alias)
        await asyncio.sleep(1)
        success = await _warmup_connection(cfg.alias)
        if success:
            await _update_host_status(host, HostStatus.CONNECTED)
            return json.dumps({"host": host, "status": "connected", "message": "Reconnection successful"}, indent=2)
        else:
            await _update_host_status(host, HostStatus.DISCONNECTED)
            return json.dumps({"host": host, "status": "failed", "hint": "Try again, or check if the host is online"}, indent=2)

    @mcp.tool()
    async def list_ssh_hosts() -> str:
        """List all hosts defined in ~/.ssh/config. Use for discovering available SSH hosts before adding them to the fleet. Read-only — does not modify any configuration."""
        from maestro.hosts import _list_ssh_config_hosts
        ssh_hosts = _list_ssh_config_hosts()
        existing_aliases = {cfg.alias for cfg in HOSTS.values()}
        result = []
        for host in ssh_hosts:
            for alias in host.get("aliases", []):
                if alias == "*":
                    continue
                result.append({
                    "alias": alias,
                    "hostname": host.get("hostname", alias),
                    "port": host.get("port", 22),
                    "user": host.get("user", ""),
                    "in_fleet": alias in existing_aliases,
                })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def add_host(
        name: str, alias: str, description: str = "",
        remote_cli: str = "codex", is_local: bool = False,
    ) -> str:
        """Add a new host to the fleet by writing to hosts.yaml and hot-reloading. IMPORTANT: This modifies the fleet configuration file. You MUST describe the proposed change and get explicit user approval before calling this tool. No password or key parameters — authentication is handled by ~/.ssh/config and SSH agent."""
        from maestro.hosts import _find_hosts_config, _parse_ssh_config, RemoteCLI, init_hosts
        import yaml

        if name in HOSTS:
            return json.dumps({"error": f"Host '{name}' already exists in fleet"})

        try:
            remote_cli_enum = RemoteCLI(remote_cli.lower())
        except ValueError:
            return json.dumps({"error": f"Invalid remote_cli '{remote_cli}'. Valid: codex, gemini, claude"})

        if not is_local:
            ssh_config = _parse_ssh_config(alias)
            if not ssh_config.get("hostname"):
                return json.dumps({"error": f"Alias '{alias}' not found in ~/.ssh/config or has no hostname"})

        hosts_path = _find_hosts_config()
        if hosts_path is None:
            hosts_path = Path(__file__).resolve().parent.parent / "hosts.yaml"

        try:
            if hosts_path.exists():
                with open(hosts_path) as f:
                    raw = yaml.safe_load(f) or {}
            else:
                raw = {"hosts": {}}
            if not isinstance(raw.get("hosts"), dict):
                raw["hosts"] = {}

            entry: dict[str, Any] = {"alias": alias, "description": description}
            if is_local:
                entry["is_local"] = True
            if remote_cli_enum != RemoteCLI.CODEX:
                entry["remote_cli"] = remote_cli_enum.value
            raw["hosts"][name] = entry

            hosts_path.parent.mkdir(parents=True, exist_ok=True)
            with open(hosts_path, "w") as f:
                yaml.dump(raw, f, default_flow_style=False, sort_keys=False)

            init_hosts(hosts_path)

            return json.dumps({"success": True, "message": f"Added host '{name}' to {hosts_path}", "host": entry}, indent=2)
        except Exception as e:
            return json.dumps({"error": f"Failed to add host: {e}"})

    # --- Agent CLI discovery ---

    @mcp.tool()
    async def agent_status(host: str = "") -> str:
        """Check Codex/Gemini/Claude Code CLI availability on a host. Also lists recent orchestra output files."""
        h = host or _local_host_name() or next(iter(HOSTS))
        try:
            _resolve_host(h)
        except ValueError as e:
            return _structured_error("validation_error", h, str(e))

        codex_rc, codex_out = await _orchestra_run_cli(h, "codex --version 2>&1", timeout=10)
        gemini_rc, gemini_out = await _orchestra_run_cli(h, "gemini --version 2>&1", timeout=10)
        claude_rc, claude_out = await _orchestra_run_cli(h, "claude --version 2>&1", timeout=10)

        output_dir = _orchestra_output_dir()
        recent = sorted(output_dir.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]

        return json.dumps({
            "host": h,
            "codex": {"available": codex_rc == 0, "output": codex_out.strip()[:200]},
            "gemini": {"available": gemini_rc == 0, "output": gemini_out.strip()[:200]},
            "claude": {"available": claude_rc == 0, "output": claude_out.strip()[:200]},
            "output_dir": str(output_dir),
            "recent_outputs": [{"name": f.name, "size": f.stat().st_size} for f in recent],
        }, indent=2)

    @mcp.tool()
    async def gemini_sessions(host: str = "") -> str:
        """List previous Gemini CLI sessions on a host."""
        h = host or _local_host_name() or next(iter(HOSTS))
        _resolve_host(h)
        rc, out = await _orchestra_run_cli(h, "gemini --list-sessions", timeout=15)
        if rc == 0:
            return json.dumps({"host": h, "sessions": out})
        return json.dumps({"host": h, "error": out})

    @mcp.tool()
    async def mux_start(
        host: str,
        command: str,
        label: str = "",
        cwd: str | None = None,
        cleanup: bool = False,
    ) -> str:
        """Run a command in a named terminal session on a host.

        The session stays alive after the command exits (for inspection) unless cleanup=True.
        Returns JSON with session name, host, and result. Use mux_read() to view output, mux_input() to interact, mux_stop() to close."""
        try:
            _resolve_mux_host(host)
            name = label or f"spawn-{secrets.token_hex(4)}"
            _validate_window_name(name)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        result = await mux_spawn(
            host,
            command,
            name,
            timeout=config.ssh_timeout,
            cwd=cwd,
            cleanup=cleanup,
        )
        return json.dumps({"host": host, "window": name, "output": result})

    @mcp.tool()
    async def mux_read(host: str, window: str, lines: int = 50) -> str:
        """Read recent output from a named terminal session on a host.

        Use to check on running commands or inspect completed ones (if window has remain-on-exit)."""
        try:
            _resolve_mux_host(host)
            _validate_window_name(window)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        result = await mux_capture(host, window, lines)
        return json.dumps({"host": host, "window": window, "content": result})

    @mcp.tool()
    async def mux_input(host: str, window: str, keys: str) -> str:
        """Provide input to a named terminal session. Use for interactive commands.

        Special keys: Enter, C-c (Ctrl+C), C-d (Ctrl+D), Escape, Tab."""
        try:
            _resolve_mux_host(host)
            _validate_window_name(window)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        await mux_send_keys(host, window, keys)
        return json.dumps({"host": host, "window": window, "sent": keys})

    @mcp.tool()
    async def mux_stop(host: str, window: str) -> str:
        """Close a named terminal session on a host. Stops the command running in it."""
        try:
            _resolve_mux_host(host)
            _validate_window_name(window)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        await mux_kill_window(host, window)
        return json.dumps({"host": host, "window": window, "status": "killed"})

    @mcp.tool()
    async def mux_list(host: str) -> str:
        """List active terminal sessions on a host. Shows what commands are currently running.

        This is the live state — for historical task records, use the tasks() tool instead."""
        try:
            _resolve_mux_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        windows = await mux_list_windows(host)
        return json.dumps({"host": host, "windows": windows})
