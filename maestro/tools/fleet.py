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

_CONFIG: MaestroConfig | None = None

# PATH fix for user-local binary installations (used in SSH non-interactive sessions)
_PATH_FIX = "export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; "


def register_tools(mcp: object, config: MaestroConfig) -> None:
    """Register all fleet + orchestra tools on the given FastMCP instance."""
    global _CONFIG
    _CONFIG = config

    from mcp.server.fastmcp import FastMCP

    assert isinstance(mcp, FastMCP)

    # --- Fleet tools ---

    @mcp.tool()
    async def exec(
        host: str, command: str, cwd: str | None = None, sudo: bool = False
    ) -> str:
        """Run a command on a host."""
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
                return await _local_run(" ".join(parts), timeout=timeout, cwd=cwd)
            return await _ssh_run(
                host, [_wrap_command(cfg, command, cwd, sudo)], timeout=timeout
            )

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="exec",
            host=host,
            prompt=command[:200],
        )

    @mcp.tool()
    async def script(
        host: str, script: str, cwd: str | None = None, sudo: bool = False
    ) -> str:
        """Run a multi-line script on a host."""
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
            return await _ssh_run(
                host, interpreter, timeout=timeout, stdin_data=stdin_body
            )

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="script",
            host=host,
            prompt=script[:200],
        )

    @mcp.tool()
    async def read(
        host: str, path: str, head: int | None = None, tail: int | None = None
    ) -> str:
        """Read a file from a host."""
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
    async def write(
        host: str, path: str, content: str, append: bool = False, sudo: bool = False
    ) -> str:
        """Write content to a file on a host."""
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
                mkdir_part = (
                    f"sudo mkdir -p {shlex.quote(parent)} && " if parent else ""
                )
                cmd = f"{mkdir_part}sudo tee {tee_flag} {quoted} > /dev/null"
            else:
                mkdir_part = f"mkdir -p {shlex.quote(parent)} && " if parent else ""
                cmd = f"{mkdir_part}tee {tee_flag} {quoted} > /dev/null"
            return await _ssh_run(host, [cmd], timeout=timeout, stdin_data=content)

    @mcp.tool()
    async def transfer(
        host: str, direction: str, local_path: str, remote_path: str
    ) -> str:
        """Transfer a file to/from a host via SCP. direction: "upload" or "download"."""
        cfg = _resolve_host(host)
        if direction == "upload":
            if cfg.is_local:
                return _local_copy(local_path, remote_path, upload=True)
            return await _scp_run(host, local_path, remote_path, upload=True)
        elif direction == "download":
            if cfg.is_local:
                return _local_copy(remote_path, local_path, upload=False)
            return await _scp_run(host, remote_path, local_path, upload=False)
        else:
            return json.dumps(
                {
                    "error": f"Invalid direction '{direction}'. Use 'upload' or 'download'."
                }
            )

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
        connected = sum(
            1 for r in results if r["status"] in ("connected", "reconnected")
        )
        return json.dumps(
            {
                "hosts": hosts_status,
                "available": connected,
                "total": len(HOSTS),
            }
        )

    # --- Orchestra tools ---

    @mcp.tool()
    async def agent_status(host: str = "") -> str:
        """Check Codex/Gemini/OpenCode/Claude CLI availability on a host."""
        h = host or _local_host_name() or next(iter(HOSTS))
        _resolve_host(h)

        codex_rc, codex_out = await _orchestra_run_cli(
            h, f"{_PATH_FIX}codex --version 2>&1", timeout=10
        )
        gemini_rc, gemini_out = await _orchestra_run_cli(
            h, f"{_PATH_FIX}gemini --version 2>&1", timeout=10
        )
        opencode_rc, opencode_out = await _orchestra_run_cli(
            h, f"{_PATH_FIX}opencode --version 2>&1", timeout=10
        )
        claude_rc, claude_out = await _orchestra_run_cli(
            h, f"{_PATH_FIX}claude --version 2>&1", timeout=10
        )

        output_dir = _orchestra_output_dir()
        recent = sorted(
            output_dir.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True
        )[:10]

        return json.dumps(
            {
                "host": h,
                "codex": {
                    "available": codex_rc == 0,
                    "output": codex_out.strip()[:200],
                },
                "gemini": {
                    "available": gemini_rc == 0,
                    "output": gemini_out.strip()[:200],
                },
                "opencode": {
                    "available": opencode_rc == 0,
                    "output": opencode_out.strip()[:200],
                },
                "claude": {
                    "available": claude_rc == 0,
                    "output": claude_out.strip()[:200],
                },
                "output_dir": str(output_dir),
                "recent_outputs": [
                    {"name": f.name, "size": f.stat().st_size} for f in recent
                ],
            },
            indent=2,
        )

    @mcp.tool()
    async def install_agent(
        host: str,
        agent: str,
        force: bool = False,
    ) -> str:
        """Install a CLI agent (opencode/codex/gemini/claude) on a remote host.

        This tool checks system requirements before installation:
        - Disk space (needs ~500MB)
        - Architecture (x86_64 or arm64)
        - Required tools (curl for opencode, npm for others)

        Note: Currently supports Linux/Unix hosts only. Windows PowerShell hosts
        are not supported for remote installation.

        Args:
            host: Target host name from fleet topology
            agent: Agent to install (opencode, codex, gemini, claude)
            force: Skip confirmation and install anyway

        Returns:
            Installation result with status and any error messages
        """
        h = host or _local_host_name() or next(iter(HOSTS))
        cfg = _resolve_host(h)

        agent = agent.lower().strip()
        valid_agents = ["opencode", "codex", "gemini", "claude"]
        if agent not in valid_agents:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Unknown agent '{agent}'. Valid options: {', '.join(valid_agents)}",
                },
                indent=2,
            )

        # Check if already installed
        check_cmd = f"{_PATH_FIX}{agent} --version 2>&1"
        rc, out = await _orchestra_run_cli(h, check_cmd, timeout=10)
        if rc == 0 and not force:
            return json.dumps(
                {
                    "success": True,
                    "already_installed": True,
                    "version": out.strip()[:100],
                    "message": f"{agent} is already installed on {h}",
                },
                indent=2,
            )

        # Check system requirements
        checks = {}

        # Architecture check
        arch_rc, arch_out = await _orchestra_run_cli(h, "uname -m", timeout=10)
        checks["architecture"] = arch_out.strip()
        if arch_out.strip() not in ["x86_64", "aarch64", "arm64"]:
            return json.dumps(
                {
                    "success": False,
                    "error": f"Unsupported architecture: {arch_out.strip()}. Need x86_64 or arm64",
                    "checks": checks,
                },
                indent=2,
            )

        # Disk space check (need ~500MB)
        disk_rc, disk_out = await _orchestra_run_cli(
            h, "df --output=avail -BG / 2>/dev/null | tail -1", timeout=10
        )
        if disk_rc == 0:
            try:
                avail_str = disk_out.strip().replace("G", "").replace(" ", "")
                if avail_str:
                    available_gb = int(avail_str)
                    checks["disk_available_gb"] = available_gb
                    if available_gb < 1:
                        return json.dumps(
                            {
                                "success": False,
                                "error": f"Insufficient disk space: {available_gb}GB available, need at least 1GB",
                                "checks": checks,
                            },
                            indent=2,
                        )
            except (ValueError, TypeError):
                pass

        # Tool-specific requirements
        if agent == "opencode":
            # OpenCode needs curl
            curl_rc, _ = await _orchestra_run_cli(h, "which curl", timeout=10)
            checks["curl_available"] = curl_rc == 0
            if curl_rc != 0:
                return json.dumps(
                    {
                        "success": False,
                        "error": "curl is required but not found. Install curl first.",
                        "checks": checks,
                    },
                    indent=2,
                )

            install_cmd = "curl -fsSL https://opencode.ai/install | bash"
        else:
            # Other agents need npm
            npm_rc, npm_out = await _orchestra_run_cli(
                h, "which npm && npm --version", timeout=10
            )
            checks["npm_available"] = npm_rc == 0
            if npm_rc != 0:
                return json.dumps(
                    {
                        "success": False,
                        "error": "npm is required for codex/gemini/claude but not found. Install Node.js first.",
                        "checks": checks,
                    },
                    indent=2,
                )
            checks["npm_version"] = npm_out.strip().split("\n")[-1][:20]

            packages = {
                "codex": "@openai/codex",
                "gemini": "@anthropic-ai/gemini-cli",
                "claude": "@anthropic-ai/claude-code",
            }
            install_cmd = f"npm install -g {packages[agent]}"

        # Execute installation
        logger.info(f"Installing {agent} on {h}: {install_cmd}")
        install_rc, install_out = await _orchestra_run_cli(
            h, install_cmd, timeout=300, cwd=None
        )

        if install_rc == 0:
            # Verify installation
            verify_rc, verify_out = await _orchestra_run_cli(
                h, f"{agent} --version", timeout=10
            )
            return json.dumps(
                {
                    "success": True,
                    "agent": agent,
                    "host": h,
                    "checks": checks,
                    "version": verify_out.strip()[:100]
                    if verify_rc == 0
                    else "installed (version check failed)",
                    "output": install_out[-500:]
                    if len(install_out) > 500
                    else install_out,
                },
                indent=2,
            )
        else:
            return json.dumps(
                {
                    "success": False,
                    "agent": agent,
                    "host": h,
                    "checks": checks,
                    "error": "Installation failed",
                    "output": install_out[-1000:]
                    if len(install_out) > 1000
                    else install_out,
                },
                indent=2,
            )

    @mcp.tool()
    async def codex(
        host: str,
        prompt: str,
        working_dir: str = config.default_repo,
        model: str = "",
        reasoning_effort: str = "xhigh",
    ) -> str:
        """Dispatch task to Codex CLI. Returns task_id."""
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
            cli_cmd = f"export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; codex exec --dangerously-bypass-approvals-and-sandbox --json {model_flag}{effort_flag}-C {shlex.quote(working_dir)} {escaped_prompt}"
            logger.info(f"Orchestra: codex on {host} [{task_id}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(
                host, cli_cmd, timeout=timeout, cwd=working_dir
            )
            return _orchestra_build_result(
                "codex", host, prompt, raw_output, rc, output_file
            )

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="codex",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def gemini_sessions(host: str = "") -> str:
        """List previous Gemini CLI sessions on a host."""
        h = host or _local_host_name() or next(iter(HOSTS))
        _resolve_host(h)
        rc, out = await _orchestra_run_cli(
            h,
            "export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; gemini --list-sessions",
            timeout=15,
        )
        return out

    @mcp.tool()
    async def opencode_sessions(host: str = "") -> str:
        """List previous OpenCode CLI sessions on a host."""
        h = host or _local_host_name() or next(iter(HOSTS))
        _resolve_host(h)
        rc, out = await _orchestra_run_cli(
            h,
            "export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; opencode session list --format json",
            timeout=15,
        )
        return out

    @mcp.tool()
    async def opencode(
        host: str,
        prompt: str,
        working_dir: str = config.default_repo,
        model: str = "",
        session_id: str = "",
    ) -> str:
        """Dispatch task to OpenCode CLI. Returns task_id."""
        ctx = get_client_context()
        timeout = config.opencode_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        task_id = _orchestra_task_id(prompt + session_id)
        output_file = _orchestra_output_path("opencode", task_id)

        async def _execute() -> str:
            model_flag = f"-m {shlex.quote(model)} " if model else ""
            session_flag = f"-s {shlex.quote(session_id)} " if session_id else ""
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            cli_cmd = f"export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; opencode run {escaped_prompt} --format json {model_flag}{session_flag}"
            logger.info(f"Orchestra: opencode on {host} [{task_id}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(
                host, cli_cmd, timeout=timeout, cwd=working_dir
            )
            return _orchestra_build_result(
                "opencode", host, prompt, raw_output, rc, output_file
            )

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="opencode",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def gemini(
        host: str,
        prompt: str,
        context_files: list[str] | None = None,
        working_dir: str = config.default_repo,
        model: str = "",
        approval_mode: str = "plan",
        resume: str = "",
    ) -> str:
        """Dispatch task to Gemini CLI.

        approval_mode: "plan" (read-only), "yolo" (auto-approve all), "auto_edit" (auto-approve edits), "default" (prompt).
        resume: Session index (e.g. "1") or "latest" to continue a previous chat.
        WARNING: Resuming a session re-sends the entire history, costing tokens for all previous turns.
        """
        ctx = get_client_context()
        timeout = config.gemini_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        task_id = _orchestra_task_id(prompt + resume)
        output_file = _orchestra_output_path("gemini", task_id)

        async def _execute() -> str:
            full_prompt = prompt
            if context_files:
                file_refs = " ".join(f"@{f}" for f in context_files)
                full_prompt = f"{file_refs} {prompt}"

            model_flag = f"--model {shlex.quote(model)} " if model else ""
            approval_flag = f"--approval-mode {shlex.quote(approval_mode)} "
            resume_flag = f"--resume {shlex.quote(resume)} " if resume else ""

            cli_cmd = (
                f"export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; gemini -p {shlex.quote(full_prompt)} --output-format json "
                f"{model_flag}{approval_flag}{resume_flag}"
            )

            logger.info(f"Orchestra: gemini on {host} [{task_id}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(
                host, cli_cmd, timeout=timeout, cwd=working_dir
            )
            return _orchestra_build_result(
                "gemini",
                host,
                prompt,
                _extract_gemini_response(raw_output),
                rc,
                output_file,
            )

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="gemini",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def read_output(
        file_path: str, start_line: int = 0, max_lines: int = 200
    ) -> str:
        """Read full or partial output from a previous agent run."""
        fp = Path(file_path)
        try:
            fp.resolve().relative_to(config.orchestra_output_dir.resolve())
        except ValueError:
            return json.dumps(
                {"error": f"Access denied: only files in {config.orchestra_output_dir}"}
            )
        if not fp.exists():
            return json.dumps({"error": f"File not found: {file_path}"})
        lines = fp.read_text(encoding="utf-8").splitlines()
        total = len(lines)
        selected = lines[start_line : start_line + max_lines]
        return json.dumps(
            {
                "file": str(fp),
                "total_lines": total,
                "start_line": start_line,
                "lines_returned": len(selected),
                "has_more": start_line + max_lines < total,
                "content": "\n".join(selected),
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    async def claude(
        host: str,
        prompt: str,
        working_dir: str = config.default_repo,
        allowed_tools: str = "Edit,Write,Bash(git:*),Read",
    ) -> str:
        """Dispatch task to Claude Code CLI. Returns task_id."""
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
                f"export PATH=$PATH:~/.local/bin:~/bin:~/.opencode/bin 2>/dev/null; claude -p {escaped_prompt} --output-format json "
                f"--permission-mode bypassPermissions "
                f"--allowedTools {escaped_tools}"
            )
            logger.info(f"Orchestra: claude on {host} [{task_id}]: {prompt[:80]}...")
            rc, raw_output = await _orchestra_run_cli(
                host, cli_cmd, timeout=timeout, cwd=working_dir
            )
            return _orchestra_build_result(
                "claude", host, prompt, raw_output, rc, output_file
            )

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="claude",
            host=host,
            prompt=prompt,
        )

    @mcp.tool()
    async def poll(task_id: str) -> str:
        """Check task status or retrieve result."""
        async with _REGISTRY_LOCK:
            ts = TASK_REGISTRY.get(task_id)
        if ts is None:
            return json.dumps({"error": f"Task '{task_id}' not found"})
        if ts.status != "running":
            return ts.result_json

        ctx = get_client_context()
        cooldown = ctx.profile["poll_cooldown"]
        now = time.time()
        since_last = now - ts.last_polled_at
        if ts.last_polled_at > 0 and since_last < cooldown:
            return json.dumps(
                {
                    "status": "cooldown",
                    "task_id": task_id,
                    "retry_after": round(cooldown - since_last, 1),
                }
            )
        ts.last_polled_at = now

        elapsed = (datetime.now(timezone.utc) - ts.started_at).total_seconds()
        return json.dumps(
            {
                "task_id": task_id,
                "agent": ts.agent,
                "host": ts.host,
                "status": "running",
                "elapsed_seconds": round(elapsed, 1),
            }
        )
