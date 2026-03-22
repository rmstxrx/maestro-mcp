"""Fleet + orchestra MCP tool functions."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
from datetime import datetime, timezone
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
    _local_run,
    _local_script,
    _local_write_file,
)
from maestro.tools.orchestra import (
    AGENT_SCOPE_PREFIX,
    _auto_promote,
    _extract_gemini_response,
    _orchestra_build_result,
    _orchestra_output_dir,
    _orchestra_output_path,
    _orchestra_run_cli,
    get_task_ledger,
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

_CONFIG: MaestroConfig | None = None
_AGENT_CLI_PATTERNS = re.compile(
    r"\b(codex|gemini|claude)\b.*(?:-[pq]|--prompt|--model|--message)(?:\s|=|$)",
    re.IGNORECASE | re.DOTALL,
)


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


def _format_relative_time(ts: datetime, now: datetime | None = None) -> str:
    """Format a timestamp as a compact relative age string."""
    current = now or datetime.now(timezone.utc)
    seconds = max(int((current - ts).total_seconds()), 0)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def register_tools(mcp: object, config: MaestroConfig) -> None:
    """Register all fleet + orchestra tools on the given FastMCP instance."""
    global _CONFIG
    _CONFIG = config

    from mcp.server.fastmcp import FastMCP
    assert isinstance(mcp, FastMCP)

    # --- Fleet tools ---

    @mcp.tool()
    async def exec(host: str, command: str, cwd: str | None = None, sudo: bool = False) -> str:
        """Run a shell command on a host. Do NOT use this to invoke agent CLIs (claude, codex, gemini) — use the dedicated dispatch tools instead."""
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
            if cfg.is_local:
                parts = []
                if sudo:
                    parts.append("sudo")
                parts.append(command)
                raw = await _local_run(" ".join(parts), timeout=timeout, cwd=cwd)
            else:
                raw = await _ssh_run(host, [_wrap_command(cfg, command, cwd, sudo)], timeout=timeout)
            return json.dumps({"_host": host, "_agent": "exec", "output": raw})

        return await _auto_promote(
            _execute, block_timeout=block_timeout,
            agent="exec", host=host, prompt=command[:200],
            client_class=ctx.classification,
        )

    @mcp.tool()
    async def script(host: str, script: str, cwd: str | None = None, sudo: bool = False) -> str:
        """Run a multi-line script on a host. Do NOT use this to invoke agent CLIs — use dedicated dispatch tools."""
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
            if cfg.is_local:
                raw = await _local_script(script, timeout=timeout, cwd=cwd, sudo=sudo)
                return json.dumps({"_host": host, "_agent": "script", "output": raw})
            lines = []
            if cfg.shell == HostShell.POWERSHELL:
                lines.append("$ErrorActionPreference = 'Stop'")
                if cwd:
                    lines.append(f"Set-Location -LiteralPath {_ps_quote(cwd)}")
                lines.append(script)
                stdin_body = "\n".join(lines)
                interpreter = ["powershell", "-Command", "-"]
            else:
                lines.append("set -euo pipefail")
                if cwd:
                    lines.append(f"cd {shlex.quote(cwd)}")
                lines.append(script)
                stdin_body = "\n".join(lines)
                interpreter = ["sudo", "bash", "-s"] if sudo else ["bash", "-s"]
            raw = await _ssh_run(host, interpreter, timeout=timeout, stdin_data=stdin_body)
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
        """Write content to a file on a host."""
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

    # --- Orchestra tools ---

    @mcp.tool()
    async def agent_status(host: str = "") -> str:
        """Check Codex/Gemini CLI availability on a host."""
        h = host or _local_host_name() or next(iter(HOSTS))
        try:
            _resolve_host(h)
        except ValueError as e:
            return _structured_error("validation_error", h, str(e))

        codex_rc, codex_out = await _orchestra_run_cli(h, "codex --version 2>&1", timeout=10)
        gemini_rc, gemini_out = await _orchestra_run_cli(h, "gemini --version 2>&1", timeout=10)

        output_dir = _orchestra_output_dir()
        recent = sorted(output_dir.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]

        return json.dumps({
            "host": h,
            "codex": {"available": codex_rc == 0, "output": codex_out.strip()[:200]},
            "gemini": {"available": gemini_rc == 0, "output": gemini_out.strip()[:200]},
            "output_dir": str(output_dir),
            "recent_outputs": [{"name": f.name, "size": f.stat().st_size} for f in recent],
        }, indent=2)

    @mcp.tool()
    async def codex(
        host: str, prompt: str, working_dir: str,
        model: str = "", reasoning_effort: str = "xhigh", timeout: int = 0,
    ) -> str:
        """Dispatch a coding task to Codex CLI. Handles flags, output capture, task registry, auto-promote. Returns task_id — use poll() for results. Prefer over exec()."""
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({"error": "validation_error", "host": host, "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}"})
        ctx = get_client_context()
        effective_timeout = timeout if timeout > 0 else config.codex_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        output_holder: list[Path | None] = [None]

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file is not None
            model_flag = f"--model {shlex.quote(model)} " if model else ""
            effort_flag = f"-c model_reasoning_effort={shlex.quote(reasoning_effort)} "
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            cli_cmd = f"codex exec --dangerously-bypass-approvals-and-sandbox --json {model_flag}{effort_flag}-C {shlex.quote(working_dir)} {escaped_prompt}"
            task_label = output_file.stem.rsplit("_", 1)[-1]
            logger.info(f"Orchestra: codex on {host} [{task_label}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=effective_timeout, cwd=working_dir)
            return _orchestra_build_result("codex", host, prompt, raw_output, rc, output_file)

        return await _auto_promote(
            _execute, block_timeout=block_timeout,
            agent="codex", host=host, prompt=prompt,
            client_class=ctx.classification,
            output_file_factory=lambda tid: _orchestra_output_path("codex", tid),
            output_holder=output_holder,
        )

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
    async def gemini(
        host: str, prompt: str, working_dir: str,
        context_files: list[str] | None = None, model: str = "",
        approval_mode: str = "plan", resume: str = "", timeout: int = 0,
    ) -> str:
        """Dispatch an analysis/research task to Gemini CLI. Exploits 1M-token context. Returns task_id — use poll() for results. Prefer over exec().

        approval_mode: "plan" (read-only), "yolo" (auto-approve all), "auto_edit" (auto-approve edits), "default" (prompt).
        resume: Session index (e.g. "1") or "latest" to continue a previous chat.
        WARNING: Resuming a session re-sends the entire history, costing tokens for all previous turns.
        """
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({"error": "validation_error", "host": host, "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}"})
        ctx = get_client_context()
        effective_timeout = timeout if timeout > 0 else config.gemini_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        output_holder: list[Path | None] = [None]

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file is not None
            full_prompt = prompt
            if context_files:
                file_refs = " ".join(f"@{f}" for f in context_files)
                full_prompt = f"{file_refs} {prompt}"

            model_flag = f"--model {shlex.quote(model)} " if model else ""
            approval_flag = f"--approval-mode {shlex.quote(approval_mode)} "
            resume_flag = f"--resume {shlex.quote(resume)} " if resume else ""

            cli_cmd = (
                f"gemini -p {shlex.quote(full_prompt)} --output-format json "
                f"{model_flag}{approval_flag}{resume_flag}"
            )

            task_label = output_file.stem.rsplit("_", 1)[-1]
            logger.info(f"Orchestra: gemini on {host} [{task_label}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=effective_timeout, cwd=working_dir)
            return _orchestra_build_result("gemini", host, prompt, _extract_gemini_response(raw_output), rc, output_file)

        return await _auto_promote(
            _execute, block_timeout=block_timeout,
            agent="gemini", host=host, prompt=prompt,
            client_class=ctx.classification,
            output_file_factory=lambda tid: _orchestra_output_path("gemini", tid),
            output_holder=output_holder,
        )

    @mcp.tool()
    async def read_output(file_path: str, start_line: int = 0, max_lines: int = 200) -> str:
        """Read full or partial output from a previous agent run."""
        fp = Path(file_path)
        try:
            fp.resolve().relative_to(config.orchestra_output_dir.resolve())
        except ValueError:
            return json.dumps({"error": f"Access denied: only files in {config.orchestra_output_dir}"})
        if not fp.exists():
            return json.dumps({"error": f"File not found: {file_path}"})
        lines = fp.read_text(encoding="utf-8").splitlines()
        total = len(lines)
        selected = lines[start_line : start_line + max_lines]
        return json.dumps({
            "file": str(fp), "total_lines": total, "start_line": start_line,
            "lines_returned": len(selected), "has_more": start_line + max_lines < total,
            "content": "\n".join(selected),
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    async def claude(
        host: str, prompt: str, working_dir: str,
        allowed_tools: str = "Edit,Write,Bash(git:*),Bash(python:*),Bash(python3:*),Bash(pip:*),Bash(cat:*),Bash(grep:*),Bash(head:*),Bash(tail:*),Bash(ls:*),Bash(find:*),Bash(mkdir:*),Bash(cp:*),Bash(sed:*),Bash(wc:*),Bash(echo:*),Bash(diff:*),Bash(timeout:*),Read", timeout: int = 0,
    ) -> str:
        """Dispatch a coding task to Claude Code CLI. Handles flags, output capture, task registry, auto-promote. Returns task_id — use poll() for results. Prefer over exec()."""
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({"error": "validation_error", "host": host, "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}"})
        ctx = get_client_context()
        effective_timeout = timeout if timeout > 0 else config.claude_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        output_holder: list[Path | None] = [None]

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file is not None
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            escaped_tools = shlex.quote(allowed_tools)
            cli_cmd = (
                f"claude -p {escaped_prompt} --output-format json "
                f"--permission-mode bypassPermissions "
                f"--allowedTools {escaped_tools}"
            )
            task_label = output_file.stem.rsplit("_", 1)[-1]
            logger.info(f"Orchestra: claude on {host} [{task_label}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=effective_timeout, cwd=working_dir)
            return _orchestra_build_result("claude", host, prompt, raw_output, rc, output_file)

        return await _auto_promote(
            _execute, block_timeout=block_timeout,
            agent="claude", host=host, prompt=prompt,
            client_class=ctx.classification,
            output_file_factory=lambda tid: _orchestra_output_path("claude", tid),
            output_holder=output_holder,
        )

    @mcp.tool()
    async def prepare_relay() -> str:
        """Prepare the file relay for use. Call once before using push/pull endpoints. Result is valid for 1 hour."""
        import secrets as _s
        from maestro.relay import register_ephemeral_token as _reg
        v = _s.token_urlsafe(32)
        _reg(v, ttl=3600)
        return json.dumps({"value": v, "ttl_seconds": 3600})

    @mcp.tool()
    async def tasks(
        status: str | None = None,
        agent: str | None = None,
        host: str | None = None,
        last: int = 10,
    ) -> str:
        """List recent tasks from the task ledger."""
        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})
        now = datetime.now(timezone.utc)
        rows = [
            {
                "task_id": entry.task_id,
                "agent": entry.agent,
                "host": entry.host,
                "status": entry.status,
                "dispatched_at": _format_relative_time(entry.dispatched_at, now),
                "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
                "return_code": entry.return_code,
                "output_file": entry.output_file,
                "result_url": entry.result_url,
            }
            for entry in ledger.query(status=status, agent=agent, host=host, last=last)
        ]
        return json.dumps({"tasks": rows}, ensure_ascii=False)

    @mcp.tool()
    async def poll(task_id: str) -> str:
        """Check task status. Returns metadata only — retrieve full results via result_url or read_output(output_file)."""
        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})
        entry = ledger.get(task_id)
        if entry is None:
            return json.dumps({"error": f"Task '{task_id}' not found"})
        result: dict[str, Any] = {
            "task_id": entry.task_id,
            "agent": entry.agent,
            "host": entry.host,
            "status": entry.status,
            "dispatched_at": entry.dispatched_at.isoformat(),
            "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
            "return_code": entry.return_code,
            "output_file": entry.output_file,
            "result_url": entry.result_url,
        }
        if entry.status == "running":
            elapsed = (datetime.now(timezone.utc) - entry.dispatched_at).total_seconds()
            result["elapsed_seconds"] = round(elapsed, 1)
        return json.dumps(result, ensure_ascii=False)
