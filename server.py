#!/usr/bin/env python3
"""
Maestro MCP — multi-host machine fleet + AI agent orchestra.

Runs as an MCP server (stdio or streamable-http) that provides shell
access, file operations, and AI agent dispatch across a heterogeneous
machine fleet. Host definitions are loaded from hosts.yaml.

The hub machine (is_local: true) executes commands directly; all other
hosts are reached via SSH ControlMaster connections.
"""

import asyncio
import argparse
import json
import logging
import os
import shlex
import time
import yaml
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable

from pydantic import AnyHttpUrl
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from maestro.config import MaestroConfig
from maestro.local import (
    _local_copy,
    _local_read_file,
    _local_run,
    _local_script,
    _local_write_file,
    configure_local,
)
from maestro.transport import (
    _async_run,
    _check_control_master,
    _ensure_connection,
    _is_transient_failure,
    _scp_run,
    _ssh_run,
    _teardown_connection,
    _warmup_connection,
    configure_transport,
    teardown_all_hosts,
    warmup_all_hosts,
)
from maestro.tools.orchestra import (
    AGENT_SCOPE_PREFIX,
    TASK_REGISTRY,
    TaskState,
    _REGISTRY_LOCK,
    _auto_promote,
    _extract_gemini_response,
    _orchestra_build_result,
    _orchestra_output_dir,
    _orchestra_output_path,
    _orchestra_run_cli,
    _orchestra_run_cli_raw,
    _orchestra_task_id,
    _orchestra_truncate,
    cancel_eviction_loop,
    configure_orchestra,
    start_eviction_loop,
)
from maestro.relay import configure_relay, transfer_push, transfer_pull
from maestro_oauth import MaestroOAuthProvider

logger = logging.getLogger("maestro")
audit_logger = logging.getLogger("maestro-audit")


def _audit(event: str, **kwargs: Any) -> None:
    entry = {"ts": time.time(), "event": event, **kwargs}
    audit_logger.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Configuration — env vars
# ---------------------------------------------------------------------------
CONFIG = MaestroConfig.from_env()
MAX_INLINE_OUTPUT = CONFIG.max_inline_output

# ---------------------------------------------------------------------------
# Host registry
# ---------------------------------------------------------------------------

class HostStatus(Enum):
    UNKNOWN = "unknown"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class HostShell(Enum):
    BASH = "bash"
    POWERSHELL = "powershell"


@dataclass
class HostConfig:
    alias: str
    display_name: str
    description: str
    shell: HostShell = HostShell.BASH
    is_local: bool = False
    status: HostStatus = HostStatus.UNKNOWN
    last_check: float = 0.0
    last_error: str = ""


def _load_hosts(config_path: Path | None = None) -> dict[str, HostConfig]:
    """Load host registry from hosts.yaml."""
    if config_path is None:
        config_path = Path(__file__).parent / "hosts.yaml"
    if not config_path.exists():
        example = Path(__file__).parent / "hosts.example.yaml"
        msg = f"Host config not found: {config_path}"
        if example.exists():
            msg += f"\n  Copy the example:  cp {example} {config_path}"
        raise SystemExit(msg)

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict) or "hosts" not in raw:
        raise SystemExit(f"Invalid hosts.yaml: expected top-level 'hosts' key in {config_path}")

    hosts: dict[str, HostConfig] = {}
    for name, cfg in raw["hosts"].items():
        if not isinstance(cfg, dict) or "alias" not in cfg:
            raise SystemExit(f"Invalid host '{name}' in {config_path}: 'alias' is required")
        shell_str = cfg.get("shell", "bash").lower()
        try:
            shell = HostShell(shell_str)
        except ValueError:
            raise SystemExit(
                f"Invalid shell '{shell_str}' for host '{name}'. "
                f"Valid options: {', '.join(s.value for s in HostShell)}"
            )
        hosts[name] = HostConfig(
            alias=cfg["alias"],
            display_name=cfg.get("display_name", name),
            description=cfg.get("description", ""),
            shell=shell,
            is_local=cfg.get("is_local", False),
        )

    if not hosts:
        raise SystemExit(f"No hosts defined in {config_path}")

    return hosts


HOSTS: dict[str, HostConfig] = _load_hosts()
_HOST_LOCKS: dict[str, asyncio.Lock] = {name: asyncio.Lock() for name in HOSTS}


async def _update_host_status(
    name: str,
    status: HostStatus,
    last_error: str = "",
) -> None:
    """Thread-safe update of host connection status."""
    config = HOSTS[name]
    async with _HOST_LOCKS[name]:
        config.status = status
        config.last_check = time.time()
        if last_error:
            config.last_error = last_error


def _local_host_name() -> str | None:
    """Return the name of the first host marked is_local, or None."""
    for name, config in HOSTS.items():
        if config.is_local:
            return name
    return None


# ---------------------------------------------------------------------------
# OAuth provider (shared instance — must exist before FastMCP constructor)
# ---------------------------------------------------------------------------
_oauth_provider = MaestroOAuthProvider(
    issuer_url=CONFIG.issuer_url,
    host_names=list(HOSTS.keys()),
)

# ---------------------------------------------------------------------------
# Execution/transport helpers extracted to maestro.local and maestro.transport
# ---------------------------------------------------------------------------

def _format_result(stdout: str, stderr: str, returncode: int) -> str:
    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(f"[stderr]\n{stderr}")
    if returncode != 0:
        parts.append(f"[exit code: {returncode}]")
    return "\n".join(parts) or "[no output]"


def _ps_quote(value: str) -> str:
    """Quote a value for PowerShell using double quotes with backtick escaping."""
    escaped = value.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f'"{escaped}"'


def _local_host_hint(tool_name: str, host_name: str) -> str:
    """Soft guardrail — kept as no-op to avoid touching call sites."""
    return ""


def _resolve_host(host: str) -> HostConfig:
    if host not in HOSTS:
        available = ", ".join(sorted(HOSTS.keys()))
        raise ValueError(f"Unknown host '{host}'. Available hosts: {available}")
    return HOSTS[host]


def _wrap_command(config: HostConfig, command: str, cwd: str | None, sudo: bool) -> str:
    if config.shell == HostShell.POWERSHELL:
        parts = []
        if cwd:
            parts.append(f"Set-Location -LiteralPath {_ps_quote(cwd)};")
        parts.append(command)
        full = " ".join(parts)
        return f"sudo {full}" if sudo else full
    else:
        parts = []
        if cwd:
            parts.append(f"cd {shlex.quote(cwd)} &&")
        if sudo:
            parts.append("sudo")
        parts.append(command)
        return " ".join(parts)


configure_transport(
    config=CONFIG,
    hosts=HOSTS,
    locks=_HOST_LOCKS,
    update_host_status=_update_host_status,
    resolve_host=_resolve_host,
    host_status=HostStatus,
    format_result=_format_result,
)
configure_local(
    config=CONFIG,
    format_result=_format_result,
)
configure_orchestra(
    config=CONFIG,
    resolve_host=_resolve_host,
    wrap_command=_wrap_command,
    format_result=_format_result,
    update_host_status=_update_host_status,
    host_status=HostStatus,
    ensure_connection=_ensure_connection,
    teardown_connection=_teardown_connection,
    async_run=_async_run,
    is_transient_failure=_is_transient_failure,
)
configure_relay(
    config=CONFIG,
    resolve_host=_resolve_host,
    scp_run=_scp_run,
)


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

def _build_instructions() -> str:
    """Generate MCP instructions dynamically from loaded hosts."""
    dispatch_rule = "All dispatch tools return a task_id. Use poll(task_id) for results."
    host_list = ", ".join(HOSTS.keys())
    instructions = f"Hosts: {host_list}. {dispatch_rule}"
    if len(instructions) <= 300:
        return instructions
    max_hosts_len = max(0, 300 - len("Hosts: . ") - len(dispatch_rule))
    trimmed_hosts = host_list[:max_hosts_len]
    if len(host_list) > max_hosts_len and max_hosts_len > 3:
        trimmed_hosts = trimmed_hosts[:-3].rstrip(", ") + "..."
    return f"Hosts: {trimmed_hosts}. {dispatch_rule}"[:300]


mcp = FastMCP(
    "maestro",
    auth_server_provider=_oauth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(CONFIG.issuer_url),
        resource_server_url=AnyHttpUrl(f"{CONFIG.issuer_url}/mcp"),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["maestro"],
            default_scopes=["maestro"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=["maestro"],
    ),
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    instructions=_build_instructions(),
)


@mcp.custom_route("/approve", methods=["GET", "POST"])
async def _approve_route(request: Request) -> Response:
    """Consent page + PIN gate for non-Claude.ai OAuth clients."""
    return await _oauth_provider.handle_approve(request)


# --- FILE TRANSFER RELAY (delegated to maestro.relay) ---

@mcp.custom_route("/transfer/push", methods=["POST"])
async def _transfer_push(request: Request) -> Response:
    return await transfer_push(request)


@mcp.custom_route("/transfer/pull", methods=["GET"])
async def _transfer_pull(request: Request) -> Response:
    return await transfer_pull(request)

@mcp.tool()
async def maestro_exec(
    host: str, command: str, cwd: str | None = None,
    sudo: bool = False, timeout: int = CONFIG.ssh_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Execute a shell command on a remote host.

    If the command takes longer than block_timeout seconds, it auto-promotes
    to a background task and returns a task_id. Use agent_poll(task_id) to
    retrieve the result.

    Args:
        host: Target host (see maestro_status for available hosts)
        command: Shell command to execute
        cwd: Working directory to cd into before running the command
        sudo: If True, prepend sudo (assumes passwordless sudo on target)
        timeout: Max seconds to wait (default from SSH_TIMEOUT env, usually 300)
        block_timeout: Max seconds to block inline before auto-promoting (default 20).
                       Use -1 to force full blocking (legacy).
    """
    async def _execute() -> str:
        config = _resolve_host(host)
        if config.is_local:
            parts = []
            if sudo:
                parts.append("sudo")
            parts.append(command)
            full_cmd = " ".join(parts)
            return await _local_run(full_cmd, timeout=timeout, cwd=cwd)
        full_cmd = _wrap_command(config, command, cwd, sudo)
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
    sudo: bool = False, timeout: int = CONFIG.ssh_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Execute a multi-line script on a remote host via stdin.

    The script is piped to bash (or powershell on Windows hosts) via `bash -s`.
    Use this instead of chaining commands with &&.

    If the script takes longer than block_timeout seconds, it auto-promotes
    to a background task and returns a task_id.

    Args:
        host: Target host (see maestro_status for available hosts)
        script: Multi-line script body (no shebang needed)
        cwd: Working directory — a `cd` is prepended to the script
        sudo: If True, run the whole script under sudo
        timeout: Max seconds to wait
        block_timeout: Max seconds to block inline before auto-promoting (default 20).
    """
    async def _execute() -> str:
        config = _resolve_host(host)
        if config.is_local:
            return await _local_script(script, timeout=timeout, cwd=cwd, sudo=sudo)
        lines = []
        if config.shell == HostShell.POWERSHELL:
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
    tail: int | None = None, timeout: int = CONFIG.ssh_timeout,
) -> str:
    """Read a text file from a remote host.

    Returns the file contents. For large files, use head/tail to slice.

    Args:
        host: Target host (see maestro_status for available hosts)
        path: Absolute path to the file on the remote host
        head: If set, return only the first N lines
        tail: If set, return only the last N lines
        timeout: Max seconds to wait
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_read_file(path, head=head, tail=tail)
    if config.shell == HostShell.POWERSHELL:
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
    return await _ssh_run(host, [cmd], timeout=timeout)


@mcp.tool()
async def maestro_write(
    host: str, path: str, content: str, append: bool = False,
    sudo: bool = False, timeout: int = CONFIG.ssh_timeout,
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
        timeout: Max seconds to wait
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_write_file(path, content, append=append, sudo=sudo)
    if config.shell == HostShell.POWERSHELL:
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
    config = _resolve_host(host)
    if config.is_local:
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
    config = _resolve_host(host)
    if config.is_local:
        return _local_copy(remote_path, local_path, upload=False)
    return await _scp_run(host, remote_path, local_path, upload=False)


@mcp.tool()
async def maestro_status() -> str:
    """Check connectivity status of all SSH hosts.

    Tests each host's ControlMaster socket and re-warms connections
    that have gone stale. Returns a status summary.
    """
    lines = ["Maestro Status", "=" * 55]

    async def _check_one(name: str, config: HostConfig) -> str:
        if config.is_local:
            await _update_host_status(name, HostStatus.CONNECTED)
            return f"  {name:12s} [{'local':10s}]  ✓ LOCAL"
        alive = await _check_control_master(config.alias)
        if alive:
            await _update_host_status(name, HostStatus.CONNECTED)
            status_str = "✓ CONNECTED"
        else:
            if await _warmup_connection(config.alias):
                await _update_host_status(name, HostStatus.CONNECTED)
                status_str = "↻ RECONNECTED"
            else:
                await _update_host_status(name, HostStatus.DISCONNECTED)
                status_str = "✗ OFFLINE"
        line = f"  {name:12s} [{config.shell.value:10s}]  {status_str}"
        if config.last_error and config.status != HostStatus.CONNECTED:
            line += f"  -- {config.last_error}"
        return line

    results = await asyncio.gather(
        *[_check_one(name, config) for name, config in HOSTS.items()]
    )
    lines.extend(results)
    connected = sum(1 for c in HOSTS.values() if c.status == HostStatus.CONNECTED)
    lines.append("=" * 55)
    lines.append(f"{connected}/{len(HOSTS)} hosts available")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent Orchestra — CLI agent dispatch tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def agent_status(host: str = "") -> str:
    """Check availability of Codex CLI and Gemini CLI on a Maestro host.

    Args:
        host: Target host (see maestro_status for available hosts)
    """
    if not host:
        host = _local_host_name() or next(iter(HOSTS))
    _resolve_host(host)

    codex_rc, codex_out = await _orchestra_run_cli(host, "codex --version 2>&1", timeout=10)
    gemini_rc, gemini_out = await _orchestra_run_cli(host, "gemini --version 2>&1", timeout=10)

    output_dir = _orchestra_output_dir()
    recent = sorted(output_dir.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]

    return json.dumps({
        "host": host,
        "codex": {"available": codex_rc == 0, "output": codex_out.strip()[:200]},
        "gemini": {"available": gemini_rc == 0, "output": gemini_out.strip()[:200]},
        "output_dir": str(output_dir),
        "recent_outputs": [{"name": f.name, "size": f.stat().st_size} for f in recent],
    }, indent=2)


@mcp.tool()
async def codex_execute(
    host: str,
    prompt: str,
    working_dir: str = CONFIG.default_repo,
    model: str = "",
    reasoning_effort: str = "xhigh",
    timeout: int = CONFIG.codex_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch a coding task to OpenAI Codex CLI on a Maestro host.

    Codex runs unsandboxed. It can read files, edit code, run commands,
    and execute tests. Best for: feature implementation, refactoring,
    bug fixes, test generation.

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The coding task. Be specific and scoped.
        working_dir: Git repo directory where Codex works.
        model: Codex model (empty=default, 'gpt-5.3-codex').
        reasoning_effort: Thinking effort level ('low', 'medium', 'high', 'xhigh'). Default 'xhigh'.
        timeout: Max seconds to wait (default 600).
        block_timeout: Inline wait before auto-promote (default 20). 0=dispatch immediately.
    """
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
    working_dir: str = CONFIG.default_repo,
    model: str = "",
    mode: str = "analyze",
    timeout: int = CONFIG.gemini_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch a task to Google Gemini CLI on a Maestro host.

    Gemini 3.1 Pro with Deep Think Mini. Modes:
      - "analyze" (default): read-only analysis, large-context review
      - "execute": write mode (--yolo) for code generation / refactoring
      - "research": web search grounding for research queries

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The task or question.
        context_files: File paths to include via @file syntax (leverages 1M context).
        working_dir: Working directory for the invocation.
        model: Gemini model (empty=default).
        mode: "analyze" (read-only), "execute" (write), or "research" (web search).
        timeout: Max seconds to wait (default 600).
        block_timeout: Inline wait before auto-promote (default 20). 0=dispatch immediately.
    """
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
        fp.resolve().relative_to(CONFIG.orchestra_output_dir.resolve())
    except ValueError:
        return json.dumps({"error": f"Access denied: only files in {CONFIG.orchestra_output_dir}"})

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
    working_dir: str = CONFIG.default_repo,
    allowed_tools: str = "Edit,Write,Bash(git:*),Read",
    timeout: int = CONFIG.claude_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch a coding task to Claude Code CLI on a Maestro host.

    Claude Code runs in bypassPermissions mode. Best for: multi-file
    refactoring, architectural changes, CLAUDE.md-aware tasks, and
    anything requiring strong reasoning over large codebases.

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The coding task. Be specific and scoped.
        working_dir: Git repo directory where Claude Code works (reads CLAUDE.md here).
        allowed_tools: Comma-separated tool whitelist (default: Edit,Write,Bash(git:*),Read).
        timeout: Max seconds to wait (default 600).
        block_timeout: Inline wait before auto-promote (default 20). 0=dispatch immediately.
    """
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
async def agent_poll(task_id: str, wait: int = 0) -> str:
    """Check the status of an async agent dispatch task.

    Returns immediately with either the running status + elapsed time,
    or the full structured result if the task has completed.

    Args:
        task_id: Task ID returned by a previous dispatch call.
        wait: Max seconds to hold connection waiting for completion (long-poll).
              0 = return immediately (default). >0 = wait up to this many seconds.
    """
    async with _REGISTRY_LOCK:
        ts = TASK_REGISTRY.get(task_id)
    if ts is None:
        return json.dumps({"error": f"Task '{task_id}' not found (completed and evicted, or never existed)"})

    if ts.status == "running" and wait > 0:
        try:
            await asyncio.wait_for(ts._done_event.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass

    if ts.status == "running":
        elapsed = (datetime.now(timezone.utc) - ts.started_at).total_seconds()
        return json.dumps({
            "task_id": task_id,
            "agent": ts.agent,
            "host": ts.host,
            "status": "running",
            "elapsed_seconds": round(elapsed, 1),
        })
    return ts.result_json


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Audit logger — JSON-lines to ~/.maestro/audit.log
    _audit_log_path = Path.home() / ".maestro" / "audit.log"
    _audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    _audit_handler = logging.FileHandler(_audit_log_path)
    _audit_handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger = logging.getLogger("maestro-audit")
    _audit_logger.addHandler(_audit_handler)
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False

    parser = argparse.ArgumentParser(description="Maestro MCP server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="streamable-http")
    parser.add_argument("--port", type=int, default=8222)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    if args.transport == "streamable-http":
        import uvicorn

        app = mcp.streamable_http_app()

        from oauth_rewrite import OAuthURLRewriteMiddleware, _parse_lan_origins
        from urllib.parse import urlparse as _urlparse

        _parsed_issuer = _urlparse(CONFIG.issuer_url)
        _canonical_host = _parsed_issuer.netloc
        _allowed_origins: dict[str, str] = {
            _canonical_host: CONFIG.issuer_url,
            "localhost:8222": "http://localhost:8222",
            "127.0.0.1:8222": "http://127.0.0.1:8222",
        }
        _lan_env = os.environ.get("MAESTRO_LAN_ORIGINS", "")
        _allowed_origins.update(_parse_lan_origins(_lan_env))
        logger.info("oauth_rewrite allowed_origins: %s", list(_allowed_origins.keys()))

        app = OAuthURLRewriteMiddleware(app, CONFIG.issuer_url, allowed_origins=_allowed_origins)

        from starlette.types import ASGIApp as _ASGIApp, Receive as _Recv, Scope as _Scp, Send as _Snd

        class _MaestroMiddleware:
            def __init__(self, inner: _ASGIApp):
                self.inner = inner

            async def __call__(self, scope: _Scp, receive: _Recv, send: _Snd) -> None:
                if scope["type"] != "http":
                    await self.inner(scope, receive, send)
                    return

                hdrs = dict(scope.get("headers", []))
                path = scope.get("path", "?")
                method = scope.get("method", "?")
                auth = hdrs.get(b"authorization", b"").decode(errors="replace")
                ua = hdrs.get(b"user-agent", b"").decode(errors="replace")
                logger.info("recv: %s %s auth=%s ua=%s", method, path,
                            auth[:40] + "..." if len(auth) > 40 else (auth or "none"),
                            ua[:60])
                await self.inner(scope, receive, send)

        app = _MaestroMiddleware(app)

        logger.info(f"maestro: starting HTTP server on {args.host}:{args.port}")

        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info", proxy_headers=True, forwarded_allow_ips="*")
        server = uvicorn.Server(config)

        async def _serve_with_maestro_lifecycle() -> None:
            logger.info("maestro: warming up connections...")
            results = await warmup_all_hosts()
            connected = sum(1 for v in results.values() if v)
            logger.info(f"maestro: {connected}/{len(results)} hosts connected")
            eviction_task = start_eviction_loop()
            try:
                await server.serve()
            finally:
                cancel_eviction_loop()
                try:
                    logger.info("maestro: shutting down, closing connections...")
                    await teardown_all_hosts()
                except Exception:
                    logger.exception("maestro: error during teardown")

        asyncio.run(_serve_with_maestro_lifecycle())
    else:
        mcp.run(transport="stdio")
