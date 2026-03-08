"""Fleet + orchestra MCP tool functions."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path

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
    TASK_REGISTRY,
    _REGISTRY_LOCK,
    _auto_promote,
    _extract_gemini_response,
    _orchestra_build_result,
    _orchestra_output_dir,
    _orchestra_output_path,
    _orchestra_run_cli,
    _orchestra_task_id,
)
from maestro.transport import (
    _check_control_master,
    _scp_run,
    _ssh_run,
    _warmup_connection,
)

logger = logging.getLogger("maestro")

# Late-bound — set by register_tools()
_CONFIG: MaestroConfig | None = None


def _cfg() -> MaestroConfig:
    if _CONFIG is None:
        raise RuntimeError("fleet tools not configured")
    return _CONFIG


def register_tools(mcp: object, config: MaestroConfig) -> None:
    """Register all fleet + orchestra tools on the given FastMCP instance."""
    global _CONFIG
    _CONFIG = config

    # We access mcp.tool() decorator below — import type here to avoid
    # circular imports at module level.
    from mcp.server.fastmcp import FastMCP
    assert isinstance(mcp, FastMCP)

    @mcp.tool()
    async def maestro_exec(
        host: str, command: str, cwd: str | None = None,
        sudo: bool = False,
    ) -> str:
        """Execute a shell command on a remote host.

        Auto-promotes to background if the command takes too long.
        Use agent_poll(task_id) to retrieve the result.

        Args:
            host: Target host (see maestro_status for available hosts)
            command: Shell command to execute
            cwd: Working directory to cd into before running the command
            sudo: If True, prepend sudo (assumes passwordless sudo on target)
        """
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
                full_cmd = " ".join(parts)
                return await _local_run(full_cmd, timeout=timeout, cwd=cwd)
            full_cmd = _wrap_command(cfg, command, cwd, sudo)
            return await _ssh_run(host, [full_cmd], timeout=timeout)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="exec",
            host=host,
            prompt=command[:200],
        )

    @mcp.tool()
    async def maestro_script(
        host: str, script: str, cwd: str | None = None,
        sudo: bool = False,
    ) -> str:
        """Execute a multi-line script on a remote host via stdin.

        The script is piped to bash (or powershell on Windows hosts) via `bash -s`.
        Auto-promotes to background if the script takes too long.

        Args:
            host: Target host (see maestro_status for available hosts)
            script: Multi-line script body (no shebang needed)
            cwd: Working directory — a `cd` is prepended to the script
            sudo: If True, run the whole script under sudo
        """
        ctx = get_client_context()
        timeout = config.ssh_timeout
        block_timeout = ctx.profile["block_timeout_exec"]

        async def _execute() -> str:
            cfg = _resolve_host(host)
            if cfg.is_local:
                return await _local_script(script, timeout=timeout, cwd=cwd, sudo=sudo)
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
            return await _ssh_run(host, interpreter, timeout=timeout, stdin_data=stdin_body)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="script",
            host=host,
            prompt=script[:200],
        )

    @mcp.tool()
    async def maestro_read(
        host: str, path: str, head: int | None = None,
        tail: int | None = None,
    ) -> str:
        """Read a text file from a remote host.

        Returns the file contents. For large files, use head/tail to slice.

        Args:
            host: Target host (see maestro_status for available hosts)
            path: Absolute path to the file on the remote host
            head: If set, return only the first N lines
            tail: If set, return only the last N lines
        """
        cfg = _resolve_host(host)
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
    async def maestro_write(
        host: str, path: str, content: str, append: bool = False,
        sudo: bool = False,
    ) -> str:
        """Write text content to a file on a remote host.

        Pipes content via stdin to tee (or Out-File on PowerShell).
        Creates parent directories automatically.

        Args:
            host: Target host (see maestro_status for available hosts)
            path: Absolute path to the file on the remote host
            content: Text content to write
            append: If True, append instead of overwrite
            sudo: If True, write with sudo privileges
        """
        cfg = _resolve_host(host)
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
    async def maestro_upload(host: str, local_path: str, remote_path: str) -> str:
        """Upload a file to a remote host via SCP.

        Use for binary files or large transfers. For text files, prefer maestro_write.

        Args:
            host: Target host (see maestro_status for available hosts)
            local_path: Local file path to upload
            remote_path: Destination path on remote host
        """
        cfg = _resolve_host(host)
        if cfg.is_local:
            return _local_copy(local_path, remote_path, upload=True)
        return await _scp_run(host, local_path, remote_path, upload=True)

    @mcp.tool()
    async def maestro_download(host: str, remote_path: str, local_path: str) -> str:
        """Download a file from a remote host via SCP.

        Use for binary files or large transfers. For text files, prefer maestro_read.

        Args:
            host: Target host (see maestro_status for available hosts)
            remote_path: File path on remote host
            local_path: Local destination path
        """
        cfg = _resolve_host(host)
        if cfg.is_local:
            return _local_copy(remote_path, local_path, upload=False)
        return await _scp_run(host, remote_path, local_path, upload=False)

    @mcp.tool()
    async def maestro_status() -> str:
        """Check connectivity status of all SSH hosts.

        Tests each host's ControlMaster socket and re-warms connections
        that have gone stale. Returns a status summary.
        """
        lines = ["Maestro Status", "=" * 55]

        async def _check_one(name: str, cfg: HostConfig) -> str:
            if cfg.is_local:
                await _update_host_status(name, HostStatus.CONNECTED)
                return f"  {name:12s} [{'local':10s}]  ✓ LOCAL"
            alive = await _check_control_master(cfg.alias)
            if alive:
                await _update_host_status(name, HostStatus.CONNECTED)
                status_str = "✓ CONNECTED"
            else:
                if await _warmup_connection(cfg.alias):
                    await _update_host_status(name, HostStatus.CONNECTED)
                    status_str = "↻ RECONNECTED"
                else:
                    await _update_host_status(name, HostStatus.DISCONNECTED)
                    status_str = "✗ OFFLINE"
            line = f"  {name:12s} [{cfg.shell.value:10s}]  {status_str}"
            if cfg.last_error and cfg.status != HostStatus.CONNECTED:
                line += f"  -- {cfg.last_error}"
            return line

        results = await asyncio.gather(
            *[_check_one(name, cfg) for name, cfg in HOSTS.items()]
        )
        lines.extend(results)
        connected = sum(1 for c in HOSTS.values() if c.status == HostStatus.CONNECTED)
        lines.append("=" * 55)
        lines.append(f"{connected}/{len(HOSTS)} hosts available")
        return "\n".join(lines)

    # --- Orchestra tools ---

    @mcp.tool()
    async def agent_status(host: str = "") -> str:
        """Check availability of Codex CLI and Gemini CLI on a Maestro host.

        Args:
            host: Target host (see maestro_status for available hosts)
        """
        h = host or _local_host_name() or next(iter(HOSTS))
        _resolve_host(h)

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
    async def codex_execute(
        host: str,
        prompt: str,
        working_dir: str = config.default_repo,
        model: str = "",
        reasoning_effort: str = "xhigh",
    ) -> str:
        """Dispatch a coding task to OpenAI Codex CLI on a Maestro host.

        Codex runs unsandboxed. It can read files, edit code, run commands,
        and execute tests. Best for: feature implementation, refactoring,
        bug fixes, test generation.

        Full output is saved to disk; a structured summary is returned.

        Args:
            host: Target host (see maestro_status for available hosts)
            prompt: The coding task. Be specific and scoped.
            working_dir: Git repo directory where Codex works.
            model: Codex model (empty=default, 'gpt-5.3-codex').
            reasoning_effort: Thinking effort level ('low', 'medium', 'high', 'xhigh'). Default 'xhigh'.
        """
        ctx = get_client_context()
        timeout = config.codex_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        task_id = _orchestra_task_id(prompt)
        output_file = _orchestra_output_path("codex", task_id)

        async def _execute() -> str:
            model_flag = f"--model {shlex.quote(model)} " if model else ""
            effort_flag = f"-c model_reasoning_effort={shlex.quote(reasoning_effort)} "
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            cli_cmd = f"codex exec --dangerously-bypass-approvals-and-sandbox --json {model_flag}{effort_flag}-C {shlex.quote(working_dir)} {escaped_prompt}"
            logger.info(f"Orchestra: codex_execute on {host} [{task_id}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=timeout, cwd=working_dir)
            return _orchestra_build_result("codex", host, prompt, raw_output, rc, output_file)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="codex",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def gemini_analyze(
        host: str,
        prompt: str,
        context_files: list[str] | None = None,
        working_dir: str = config.default_repo,
        model: str = "",
        mode: str = "analyze",
    ) -> str:
        """Dispatch a task to Google Gemini CLI on a Maestro host.

        Gemini 3.1 Pro with Deep Think Mini. Modes:
          - "analyze" (default): read-only analysis, large-context review
          - "execute": write mode (--yolo) for code generation / refactoring
          - "research": web search grounding for research queries

        Full output is saved to disk; a structured summary is returned.

        Args:
            host: Target host (see maestro_status for available hosts)
            prompt: The task or question.
            context_files: File paths to include via @file syntax (leverages 1M context).
            working_dir: Working directory for the invocation.
            model: Gemini model (empty=default).
            mode: "analyze" (read-only), "execute" (write), or "research" (web search).
        """
        ctx = get_client_context()
        timeout = config.gemini_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        task_id = _orchestra_task_id(prompt)
        agent_label = "gemini_research" if mode == "research" else "gemini"
        output_file = _orchestra_output_path(agent_label, task_id)

        async def _execute() -> str:
            if mode == "research":
                research_prompt = (
                    f"Research the following topic thoroughly using web search. "
                    f"Provide a comprehensive answer with sources.\n\n{prompt}"
                )
                escaped = shlex.quote(research_prompt)
                cli_cmd = f"gemini -p {escaped} --output-format json"
                logger.info(f"Orchestra: gemini_research on {host} [{task_id}]: {prompt[:80]}...")
                rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=timeout)
            else:
                full_prompt = prompt
                if context_files:
                    file_refs = " ".join(f"@{f}" for f in context_files)
                    full_prompt = f"{file_refs} {prompt}"
                escaped_prompt = shlex.quote(full_prompt)
                model_flag = f"--model {shlex.quote(model)} " if model else ""
                yolo_flag = "--yolo " if mode == "execute" else ""
                cli_cmd = f"gemini -p {escaped_prompt} --output-format json {model_flag}{yolo_flag}"
                logger.info(f"Orchestra: gemini_{mode} on {host} [{task_id}]: {prompt[:80]}...")
                rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=timeout, cwd=working_dir)
            return _orchestra_build_result("gemini", host, prompt, _extract_gemini_response(raw_output), rc, output_file)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="gemini",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def agent_read_output(
        file_path: str,
        start_line: int = 0,
        max_lines: int = 200,
    ) -> str:
        """Read full or partial output from a previous agent invocation.

        When a codex_execute or gemini_analyze result was truncated,
        use this to read the full output selectively with pagination.

        Args:
            file_path: Absolute path to output file (from previous tool results).
            start_line: Start reading from this line (0-indexed).
            max_lines: Maximum lines to return (1-1000).
        """
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
            "file": str(fp),
            "total_lines": total,
            "start_line": start_line,
            "lines_returned": len(selected),
            "has_more": start_line + max_lines < total,
            "content": "\n".join(selected),
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    async def claude_execute(
        host: str,
        prompt: str,
        working_dir: str = config.default_repo,
        allowed_tools: str = "Edit,Write,Bash(git:*),Read",
    ) -> str:
        """Dispatch a coding task to Claude Code CLI on a Maestro host.

        Claude Code runs in bypassPermissions mode. Best for: multi-file
        refactoring, architectural changes, CLAUDE.md-aware tasks, and
        anything requiring strong reasoning over large codebases.

        Full output is saved to disk; a structured summary is returned.

        Args:
            host: Target host (see maestro_status for available hosts)
            prompt: The coding task. Be specific and scoped.
            working_dir: Git repo directory where Claude Code works (reads CLAUDE.md here).
            allowed_tools: Comma-separated tool whitelist (default: Edit,Write,Bash(git:*),Read).
        """
        ctx = get_client_context()
        timeout = config.claude_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        task_id = _orchestra_task_id(prompt)
        output_file = _orchestra_output_path("claude", task_id)

        async def _execute() -> str:
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            escaped_tools = shlex.quote(allowed_tools)
            cli_cmd = (
                f"claude -p {escaped_prompt} --output-format json "
                f"--permission-mode bypassPermissions "
                f"--allowedTools {escaped_tools}"
            )
            logger.info(f"Orchestra: claude_execute on {host} [{task_id}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=timeout, cwd=working_dir)
            return _orchestra_build_result("claude", host, prompt, raw_output, rc, output_file)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="claude",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def agent_poll(task_id: str) -> str:
        """Check the status of an async agent dispatch task.

        Returns the running status + elapsed time, or the full structured
        result if the task has completed. Subject to per-client poll cooldown.

        Args:
            task_id: Task ID returned by a previous dispatch call.
        """
        async with _REGISTRY_LOCK:
            ts = TASK_REGISTRY.get(task_id)
        if ts is None:
            return json.dumps({"error": f"Task '{task_id}' not found (completed and evicted, or never existed)"})

        if ts.status != "running":
            return ts.result_json

        ctx = get_client_context()
        cooldown = ctx.profile["poll_cooldown"]
        now = time.time()
        since_last = now - ts.last_polled_at
        if ts.last_polled_at > 0 and since_last < cooldown:
            retry_after = round(cooldown - since_last, 1)
            return json.dumps({
                "status": "cooldown",
                "task_id": task_id,
                "retry_after": retry_after,
            })
        ts.last_polled_at = now

        elapsed = (datetime.now(timezone.utc) - ts.started_at).total_seconds()
        return json.dumps({
            "task_id": task_id,
            "agent": ts.agent,
            "host": ts.host,
            "status": "running",
            "elapsed_seconds": round(elapsed, 1),
        })
