#!/usr/bin/env python3
"""
fleet-ssh v4 (Apollyon edition): MCP server for Rômulo's machine fleet.

This is the Apollyon-hosted variant — designed to run as a persistent
streamable-http service behind a Cloudflare Tunnel, so Cowork (cloud VM)
can reach the fleet over HTTPS.

Differences from the Judas edition:
  - Apollyon is the local host (direct subprocess, no SSH)
  - Judas is a remote host (SSH to judas.home)
  - Bearer token authentication for public-facing endpoint
"""

import asyncio
import argparse
import hashlib
import hmac
import logging
import os
import secrets
import shlex
import shutil
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("fleet-ssh")

# ---------------------------------------------------------------------------
# Host registry — Apollyon-centric topology
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


HOSTS: dict[str, HostConfig] = {
    "apollyon": HostConfig(
        alias="mcp-apollyon",
        display_name="apollyon",
        description="DGX Spark GB10, 128GB unified. LOCAL (direct execution).",
        is_local=True,  # <-- THIS is the key difference from Judas edition
    ),
    "eden": HostConfig(
        alias="mcp-eden",
        display_name="eden",
        description="Ryzen 9900X, 96GB DDR5, RTX 5090 32GB. Windows/PowerShell.",
        shell=HostShell.POWERSHELL,
    ),
    "eden-wsl": HostConfig(
        alias="mcp-eden-wsl",
        display_name="eden-wsl",
        description="Same box as eden, WSL2/Linux (ProxyJump via eden).",
    ),
    "judas": HostConfig(
        alias="mcp-judas",
        display_name="judas",
        description="MacBook Pro M3 Max, 36GB. Remote (SSH to judas.home).",
    ),
}

TIMEOUT = int(os.environ.get("SSH_TIMEOUT", "300"))
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1.0

# ---------------------------------------------------------------------------
# Async subprocess primitives
# ---------------------------------------------------------------------------

async def _async_run(
    args: list[str],
    timeout: int = 15,
    stdin_data: str | None = None,
) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
        return (
            proc.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"binary not found: {e}"


# ---------------------------------------------------------------------------
# Local execution (apollyon — no SSH)
# ---------------------------------------------------------------------------

async def _local_run(
    command: str,
    timeout: int = TIMEOUT,
    stdin_data: str | None = None,
    cwd: str | None = None,
) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
            cwd=cwd,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
        rc = proc.returncode or 0
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        return _format_result(stdout, stderr, rc)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"[local timeout after {timeout}s]"
    except FileNotFoundError as e:
        return f"[local error] binary not found: {e}"


async def _local_script(
    script: str,
    timeout: int = TIMEOUT,
    cwd: str | None = None,
    sudo: bool = False,
) -> str:
    lines = ["set -euo pipefail"]
    if cwd:
        lines.append(f"cd {shlex.quote(cwd)}")
    lines.append(script)
    stdin_body = "\n".join(lines)
    shell_cmd = ["sudo", "bash", "-s"] if sudo else ["bash", "-s"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *shell_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_body.encode()),
            timeout=timeout,
        )
        rc = proc.returncode or 0
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        return _format_result(stdout, stderr, rc)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"[local timeout after {timeout}s]"


def _local_read_file(
    path: str,
    head: int | None = None,
    tail: int | None = None,
) -> str:
    try:
        p = Path(path)
        if not p.exists():
            return f"[error] file not found: {path}"
        if not p.is_file():
            return f"[error] not a file: {path}"
        text = p.read_text(errors="replace")
        lines = text.splitlines(keepends=True)
        if head is not None:
            lines = lines[:head]
        elif tail is not None:
            lines = lines[-tail:]
        return "".join(lines) or "[empty file]"
    except PermissionError:
        return f"[error] permission denied: {path}"
    except Exception as e:
        return f"[error] {e}"


def _local_write_file(
    path: str,
    content: str,
    append: bool = False,
    sudo: bool = False,
) -> str:
    if sudo:
        import subprocess
        p = Path(path)
        parent = str(p.parent)
        try:
            if parent:
                subprocess.run(["sudo", "mkdir", "-p", parent], check=True, capture_output=True, timeout=10)
            flag = "-a" if append else ""
            cmd = f"sudo tee {flag} {shlex.quote(path)} > /dev/null"
            subprocess.run(cmd, shell=True, input=content.encode(), check=True, capture_output=True, timeout=30)
            return f"[OK] wrote {len(content)} bytes to {path} (sudo)"
        except subprocess.CalledProcessError as e:
            return f"[error] sudo write failed: {e.stderr.decode(errors='replace')}"
        except subprocess.TimeoutExpired:
            return f"[error] sudo write timed out"
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        p.write_text(content) if not append else p.open(mode).write(content)
        return f"[OK] wrote {len(content)} bytes to {path}"
    except PermissionError:
        return f"[error] permission denied: {path} (try sudo=True)"
    except Exception as e:
        return f"[error] {e}"


def _local_copy(source: str, destination: str, upload: bool) -> str:
    src = source
    dst = destination
    try:
        dst_path = Path(dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return f"[OK] copied {src} -> {dst}"
    except FileNotFoundError:
        return f"[error] source not found: {src}"
    except PermissionError:
        return f"[error] permission denied"
    except Exception as e:
        return f"[error] {e}"


# ---------------------------------------------------------------------------
# SSH ControlMaster management (remote hosts)
# ---------------------------------------------------------------------------

async def _check_control_master(alias: str) -> bool:
    rc, _, _ = await _async_run(["ssh", "-O", "check", alias], timeout=5)
    return rc == 0


async def _warmup_connection(alias: str) -> bool:
    rc, _, _ = await _async_run(["ssh", alias, "true"], timeout=15)
    return rc == 0


async def _teardown_connection(alias: str) -> None:
    await _async_run(["ssh", "-O", "exit", alias], timeout=5)


async def warmup_all_hosts() -> dict[str, bool]:
    async def _warmup_one(name: str, config: HostConfig) -> tuple[str, bool]:
        if config.is_local:
            config.status = HostStatus.CONNECTED
            config.last_check = time.time()
            logger.info(f"{name}: local host (no SSH needed)")
            return name, True
        if await _check_control_master(config.alias):
            logger.info(f"{name}: ControlMaster already active")
            config.status = HostStatus.CONNECTED
            config.last_check = time.time()
            return name, True
        logger.info(f"{name}: warming up connection...")
        success = await _warmup_connection(config.alias)
        config.status = HostStatus.CONNECTED if success else HostStatus.DISCONNECTED
        config.last_check = time.time()
        if success:
            logger.info(f"{name}: connected")
        else:
            logger.warning(f"{name}: warmup failed (host may be offline)")
        return name, success

    tasks = [_warmup_one(name, config) for name, config in HOSTS.items()]
    pairs = await asyncio.gather(*tasks)
    return dict(pairs)


async def teardown_all_hosts() -> None:
    tasks = []
    for name, config in HOSTS.items():
        if config.is_local:
            continue
        logger.info(f"{name}: tearing down ControlMaster")
        tasks.append(_teardown_connection(config.alias))
        config.status = HostStatus.DISCONNECTED
    if tasks:
        await asyncio.gather(*tasks)


# ---------------------------------------------------------------------------
# Remote SSH execution with retry
# ---------------------------------------------------------------------------

TRANSIENT_INDICATORS = [
    "Connection refused", "Connection timed out", "Connection reset",
    "Broken pipe", "Control socket connect", "No route to host",
    "Network is unreachable", "ssh_exchange_identification",
    "Connection closed by remote host",
    "mux_client_request_session: session request failed",
]


def _is_transient_failure(returncode: int, stderr: str) -> bool:
    if returncode not in (-1, 255):
        return False
    return any(ind in stderr for ind in TRANSIENT_INDICATORS)


async def _ensure_connection(alias: str) -> bool:
    if await _check_control_master(alias):
        return True
    logger.info(f"ControlMaster for {alias} is dead, re-warming...")
    return await _warmup_connection(alias)


def _format_result(stdout: str, stderr: str, returncode: int) -> str:
    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(f"[stderr]\n{stderr}")
    if returncode != 0:
        parts.append(f"[exit code: {returncode}]")
    return "\n".join(parts) or "[no output]"


def _local_host_hint(tool_name: str) -> str:
    """Soft guardrail: nudge agents to prefer native tools for local ops."""
    return (
        f"[NOTE: '{tool_name}' targeted apollyon, which is the LOCAL hub. "
        "If you have native shell/file tools (e.g. bash_tool), prefer those "
        "for local operations. If fleet-ssh is your only interface, disregard.]\n"
    )



async def _ssh_run(
    host_name: str,
    ssh_args: list[str],
    timeout: int = TIMEOUT,
    stdin_data: str | None = None,
) -> str:
    config = _resolve_host(host_name)
    last_error = ""
    for attempt in range(1, MAX_RETRIES + 1):
        await _ensure_connection(config.alias)
        rc, stdout, stderr = await _async_run(
            ["ssh", config.alias, *ssh_args],
            timeout=timeout,
            stdin_data=stdin_data,
        )
        if rc not in (-1, 255):
            config.status = HostStatus.CONNECTED
            config.last_check = time.time()
            return _format_result(stdout, stderr, rc)
        if not _is_transient_failure(rc, stderr):
            config.status = HostStatus.ERROR
            config.last_error = stderr.strip()
            return f"[SSH error on {host_name}]\n{stderr}"
        last_error = stderr.strip() or f"rc={rc}"
        logger.warning(f"{host_name}: transient failure (attempt {attempt}/{MAX_RETRIES}): {last_error}")
        if attempt < MAX_RETRIES:
            backoff = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.info(f"Retrying in {backoff}s...")
            await asyncio.sleep(backoff)
            await _teardown_connection(config.alias)
    config.status = HostStatus.ERROR
    config.last_error = last_error
    return f"[failed after {MAX_RETRIES} attempts on {host_name}]\nLast error: {last_error}"


def _resolve_host(host: str) -> HostConfig:
    if host not in HOSTS:
        available = ", ".join(sorted(HOSTS.keys()))
        raise ValueError(f"Unknown host '{host}'. Available hosts: {available}")
    return HOSTS[host]


def _wrap_command(config: HostConfig, command: str, cwd: str | None, sudo: bool) -> str:
    if config.shell == HostShell.POWERSHELL:
        parts = []
        if cwd:
            parts.append(f"Set-Location {shlex.quote(cwd)};")
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


# ---------------------------------------------------------------------------
# SCP with retry (remote hosts)
# ---------------------------------------------------------------------------

async def _scp_run(
    host_name: str,
    source: str,
    destination: str,
    upload: bool = True,
    timeout: int = TIMEOUT,
) -> str:
    config = _resolve_host(host_name)
    if upload:
        scp_args = ["scp", source, f"{config.alias}:{destination}"]
        action_desc = f"upload {source} -> {host_name}:{destination}"
    else:
        scp_args = ["scp", f"{config.alias}:{source}", destination]
        action_desc = f"download {host_name}:{source} -> {destination}"
    last_error = ""
    for attempt in range(1, MAX_RETRIES + 1):
        await _ensure_connection(config.alias)
        rc, stdout, stderr = await _async_run(scp_args, timeout=timeout)
        if rc == 0:
            config.status = HostStatus.CONNECTED
            return f"[OK] {action_desc}"
        if not _is_transient_failure(rc, stderr):
            return f"[scp failed on {host_name}]\n{stderr}"
        last_error = stderr.strip()
        logger.warning(f"{host_name}: scp transient failure (attempt {attempt}/{MAX_RETRIES}): {last_error}")
        if attempt < MAX_RETRIES:
            backoff = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            await asyncio.sleep(backoff)
            await _teardown_connection(config.alias)
    config.status = HostStatus.ERROR
    config.last_error = last_error
    return f"[scp failed after {MAX_RETRIES} attempts on {host_name}]\n{last_error}"


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def fleet_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    logger.info("fleet-ssh: warming up connections...")
    results = await warmup_all_hosts()
    connected = sum(1 for v in results.values() if v)
    total = len(results)
    logger.info(f"fleet-ssh: {connected}/{total} hosts connected")
    try:
        yield {"hosts": HOSTS, "warmup_results": results}
    finally:
        logger.info("fleet-ssh: shutting down, closing connections...")
        await teardown_all_hosts()


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "fleet-ssh",
    instructions=(
        "Unified multi-host server for Rômulo's machine fleet.\n"
        "\n"
        "Available hosts:\n"
        "  apollyon  — DGX Spark GB10, 128GB. LOCAL (direct execution, no SSH).\n"
        "  eden      — Ryzen 9900X, 96GB DDR5, RTX 5090. Windows/PowerShell.\n"
        "  eden-wsl  — Same physical machine as eden, but WSL2/Linux.\n"
        "  judas     — MacBook Pro M3 Max, 36GB. Remote (SSH).\n"
        "\n"
        "Tool guide:\n"
        "  ssh_exec      — Single command. Has cwd and sudo options.\n"
        "  ssh_script    — Multi-line script piped via stdin. Use for sequences.\n"
        "  ssh_read_file — Read a text file. Supports line range slicing.\n"
        "  ssh_write_file— Write content to a file.\n"
        "  ssh_upload / ssh_download — SCP (remote) or copy (local) for file transfers.\n"
        "  ssh_status    — Check connectivity of all hosts.\n"
        "\n"
        "Apollyon commands execute locally (zero overhead, no SSH).\n"
        "Use 'eden' for PowerShell, 'eden-wsl' for Linux on the same box.\n"
        "Prefer ssh_read_file/ssh_write_file over scp for text files.\n"
        "Prefer ssh_script over chained && commands.\n"
    ),
    lifespan=fleet_lifespan,
)


@mcp.tool()
async def ssh_exec(
    host: str, command: str, cwd: str | None = None,
    sudo: bool = False, timeout: int = TIMEOUT,
) -> str:
    """Execute a shell command on a remote host.

    Args:
        host: Target host. One of: apollyon, eden, eden-wsl, judas
        command: Shell command to execute
        cwd: Working directory to cd into before running the command
        sudo: If True, prepend sudo (assumes passwordless sudo on target)
        timeout: Max seconds to wait (default from SSH_TIMEOUT env, usually 300)
    """
    config = _resolve_host(host)
    if config.is_local:
        parts = []
        if sudo:
            parts.append("sudo")
        parts.append(command)
        full_cmd = " ".join(parts)
        return _local_host_hint("ssh_exec") + await _local_run(full_cmd, timeout=timeout, cwd=cwd)
    full_cmd = _wrap_command(config, command, cwd, sudo)
    return await _ssh_run(host, [full_cmd], timeout=timeout)


@mcp.tool()
async def ssh_script(
    host: str, script: str, cwd: str | None = None,
    sudo: bool = False, timeout: int = TIMEOUT,
) -> str:
    """Execute a multi-line script on a remote host via stdin.

    The script is piped to bash (or powershell on eden) via `bash -s`.
    Use this instead of chaining commands with &&.

    Args:
        host: Target host. One of: apollyon, eden, eden-wsl, judas
        script: Multi-line script body (no shebang needed)
        cwd: Working directory — a `cd` is prepended to the script
        sudo: If True, run the whole script under sudo
        timeout: Max seconds to wait
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_host_hint("ssh_script") + await _local_script(script, timeout=timeout, cwd=cwd, sudo=sudo)
    lines = []
    if config.shell == HostShell.POWERSHELL:
        lines.append("$ErrorActionPreference = 'Stop'")
        if cwd:
            lines.append(f"Set-Location {shlex.quote(cwd)}")
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


@mcp.tool()
async def ssh_read_file(
    host: str, path: str, head: int | None = None,
    tail: int | None = None, timeout: int = TIMEOUT,
) -> str:
    """Read a text file from a remote host.

    Returns the file contents. For large files, use head/tail to slice.

    Args:
        host: Target host. One of: apollyon, eden, eden-wsl, judas
        path: Absolute path to the file on the remote host
        head: If set, return only the first N lines
        tail: If set, return only the last N lines
        timeout: Max seconds to wait
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_host_hint("ssh_read_file") + _local_read_file(path, head=head, tail=tail)
    if config.shell == HostShell.POWERSHELL:
        if head:
            cmd = f"Get-Content {shlex.quote(path)} -TotalCount {head}"
        elif tail:
            cmd = f"Get-Content {shlex.quote(path)} -Tail {tail}"
        else:
            cmd = f"Get-Content {shlex.quote(path)}"
    else:
        if head:
            cmd = f"head -n {head} {shlex.quote(path)}"
        elif tail:
            cmd = f"tail -n {tail} {shlex.quote(path)}"
        else:
            cmd = f"cat {shlex.quote(path)}"
    return await _ssh_run(host, [cmd], timeout=timeout)


@mcp.tool()
async def ssh_write_file(
    host: str, path: str, content: str, append: bool = False,
    sudo: bool = False, timeout: int = TIMEOUT,
) -> str:
    """Write text content to a file on a remote host.

    Pipes content via stdin to tee (or Out-File on PowerShell).
    Creates parent directories automatically.

    Args:
        host: Target host. One of: apollyon, eden, eden-wsl, judas
        path: Absolute path to the file on the remote host
        content: Text content to write
        append: If True, append instead of overwrite
        sudo: If True, write with sudo privileges
        timeout: Max seconds to wait
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_host_hint("ssh_write_file") + _local_write_file(path, content, append=append, sudo=sudo)
    if config.shell == HostShell.POWERSHELL:
        if append:
            cmd = f"$input | Out-File -Append -FilePath {shlex.quote(path)}"
        else:
            cmd = f"$input | Out-File -FilePath {shlex.quote(path)}"
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
async def ssh_upload(host: str, local_path: str, remote_path: str) -> str:
    """Upload a file to a remote host via SCP.

    Use for binary files or large transfers. For text files, prefer ssh_write_file.

    Args:
        host: Target host. One of: apollyon, eden, eden-wsl, judas
        local_path: Local file path to upload
        remote_path: Destination path on remote host
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_host_hint("ssh_upload") + _local_copy(local_path, remote_path, upload=True)
    return await _scp_run(host, local_path, remote_path, upload=True)


@mcp.tool()
async def ssh_download(host: str, remote_path: str, local_path: str) -> str:
    """Download a file from a remote host via SCP.

    Use for binary files or large transfers. For text files, prefer ssh_read_file.

    Args:
        host: Target host. One of: apollyon, eden, eden-wsl, judas
        remote_path: File path on remote host
        local_path: Local destination path
    """
    config = _resolve_host(host)
    if config.is_local:
        return _local_host_hint("ssh_download") + _local_copy(remote_path, local_path, upload=False)
    return await _scp_run(host, remote_path, local_path, upload=False)


@mcp.tool()
async def ssh_status() -> str:
    """Check connectivity status of all SSH hosts.

    Tests each host's ControlMaster socket and re-warms connections
    that have gone stale. Returns a status summary.
    """
    lines = ["Fleet Status (Apollyon hub)", "=" * 55]

    async def _check_one(name: str, config: HostConfig) -> str:
        config.last_check = time.time()
        if config.is_local:
            config.status = HostStatus.CONNECTED
            return f"  {name:12s} [{'local':10s}]  ✓ LOCAL"
        alive = await _check_control_master(config.alias)
        if alive:
            config.status = HostStatus.CONNECTED
            status_str = "✓ CONNECTED"
        else:
            if await _warmup_connection(config.alias):
                config.status = HostStatus.CONNECTED
                status_str = "↻ RECONNECTED"
            else:
                config.status = HostStatus.DISCONNECTED
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
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Audit logger — JSON-lines to ~/.fleet-ssh/audit.log
    _audit_log_path = Path.home() / ".fleet-ssh" / "audit.log"
    _audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    _audit_handler = logging.FileHandler(_audit_log_path)
    _audit_handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger = logging.getLogger("fleet-audit")
    _audit_logger.addHandler(_audit_handler)
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False

    parser = argparse.ArgumentParser(description="fleet-ssh MCP server (Apollyon edition)")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="streamable-http")
    parser.add_argument("--port", type=int, default=8222)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    if args.transport == "streamable-http":
        import uvicorn

        app = mcp.streamable_http_app()

        # --- Auth + proxy middleware ---
        from starlette.types import ASGIApp, Receive, Scope, Send
        from fleet_oauth import FleetOAuthMiddleware

        _token_path = Path.home() / ".fleet-ssh" / "bearer_token"
        if _token_path.exists():
            _expected_token = _token_path.read_text().strip()
            logger.info(f"Bearer auth enabled (token from {_token_path})")
        else:
            _expected_token = os.environ.get("FLEET_SSH_TOKEN")
            if _expected_token:
                logger.info("Bearer auth enabled (token from env)")
            else:
                logger.warning("No bearer token — endpoint is UNPROTECTED")

        # Host header rewrite for reverse proxy
        class HostRewriteMiddleware:
            def __init__(self, app: ASGIApp):
                self.app = app
            async def __call__(self, scope: Scope, receive: Receive, send: Send):
                if scope['type'] in ('http', 'websocket'):
                    new_headers = []
                    for k, v in scope.get('headers', []):
                        if k == b'host':
                            new_headers.append((b'host', b'127.0.0.1:8222'))
                        else:
                            new_headers.append((k, v))
                    scope = dict(scope)
                    scope['headers'] = new_headers
                await self.app(scope, receive, send)

        # Stack: request → OAuth/BearerAuth → HostRewrite → MCP app
        app = HostRewriteMiddleware(app)
        app = FleetOAuthMiddleware(
            app=app,
            bearer_token=_expected_token,
            issuer_url="https://fleet.rmstxrx.dev",
        )

        logger.info(f"fleet-ssh: starting HTTP server on {args.host}:{args.port}")

        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info", proxy_headers=True, forwarded_allow_ips="*")
        server = uvicorn.Server(config)

        async def _serve_with_fleet_lifecycle() -> None:
            logger.info("fleet-ssh: warming up connections...")
            results = await warmup_all_hosts()
            connected = sum(1 for v in results.values() if v)
            logger.info(f"fleet-ssh: {connected}/{len(results)} hosts connected")
            try:
                await server.serve()
            finally:
                logger.info("fleet-ssh: shutting down, closing connections...")
                await teardown_all_hosts()

        asyncio.run(_serve_with_fleet_lifecycle())
    else:
        mcp.run(transport="stdio")
