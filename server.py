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
import hashlib
import hmac
import json
import logging
import os
import secrets
import shlex
import shutil
import time
import tempfile
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
from starlette.responses import Response, JSONResponse, FileResponse
from starlette.background import BackgroundTask

from maestro.config import MaestroConfig
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
AGENT_SCOPE_PREFIX = (
    "SCOPE CONSTRAINTS (non-negotiable):\n"
    "1. ONLY modify files and code directly related to the task below.\n"
    "2. Do NOT refactor, clean up, or improve code outside the task scope.\n"
    "3. Do NOT run tests unless explicitly asked.\n"
    "4. Do NOT write or update documentation unless explicitly asked.\n"
    "5. When done, output ONLY: files changed + one-sentence summary per file.\n"
    "6. If the task is ambiguous, do the MINIMUM viable interpretation.\n\n"
    "TASK:\n"
)

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
# Local execution (hub — no SSH)
# ---------------------------------------------------------------------------

async def _local_run(
    command: str,
    timeout: int = CONFIG.ssh_timeout,
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
    timeout: int = CONFIG.ssh_timeout,
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
        if append:
            with p.open("a") as f:
                f.write(content)
        else:
            p.write_text(content)
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
            await _update_host_status(name, HostStatus.CONNECTED)
            logger.info(f"{name}: local host (no SSH needed)")
            return name, True
        if await _check_control_master(config.alias):
            logger.info(f"{name}: ControlMaster already active")
            await _update_host_status(name, HostStatus.CONNECTED)
            return name, True
        logger.info(f"{name}: warming up connection...")
        success = await _warmup_connection(config.alias)
        status = HostStatus.CONNECTED if success else HostStatus.DISCONNECTED
        await _update_host_status(name, status)
        if success:
            logger.info(f"{name}: connected")
        else:
            logger.warning(f"{name}: warmup failed (host may be offline)")
        return name, success

    tasks = [_warmup_one(name, config) for name, config in HOSTS.items()]
    pairs = await asyncio.gather(*tasks)
    return dict(pairs)


async def teardown_all_hosts() -> None:
    names = []
    tasks = []
    for name, config in HOSTS.items():
        if config.is_local:
            continue
        logger.info(f"{name}: tearing down ControlMaster")
        names.append(name)
        tasks.append(_teardown_connection(config.alias))
        config.status = HostStatus.DISCONNECTED
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                logger.warning(f"Teardown failed for {name}: {result}")


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


async def _ensure_connection(alias: str, host_name: str) -> bool:
    """Ensure ControlMaster is alive, serialized per host to avoid reconnection races."""
    async with _HOST_LOCKS[host_name]:
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


def _ps_quote(value: str) -> str:
    """Quote a value for PowerShell using double quotes with backtick escaping."""
    escaped = value.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f'"{escaped}"'


def _local_host_hint(tool_name: str, host_name: str) -> str:
    """Soft guardrail — kept as no-op to avoid touching 6 call sites.

    The local-tool-preference guidance lives in _build_instructions() instead,
    where it's seen once per session rather than on every single tool result.
    """
    return ""



async def _ssh_run(
    host_name: str,
    ssh_args: list[str],
    timeout: int = CONFIG.ssh_timeout,
    stdin_data: str | None = None,
) -> str:
    config = _resolve_host(host_name)
    last_error = ""
    for attempt in range(1, CONFIG.max_retries + 1):
        await _ensure_connection(config.alias, host_name)
        rc, stdout, stderr = await _async_run(
            ["ssh", config.alias, *ssh_args],
            timeout=timeout,
            stdin_data=stdin_data,
        )
        if rc not in (-1, 255):
            await _update_host_status(host_name, HostStatus.CONNECTED)
            return _format_result(stdout, stderr, rc)
        if not _is_transient_failure(rc, stderr):
            await _update_host_status(host_name, HostStatus.ERROR, last_error=stderr.strip())
            return f"[SSH error on {host_name}]\n{stderr}"
        last_error = stderr.strip() or f"rc={rc}"
        logger.warning(f"{host_name}: transient failure (attempt {attempt}/{CONFIG.max_retries}): {last_error}")
        if attempt < CONFIG.max_retries:
            backoff = CONFIG.retry_backoff_base * (2 ** (attempt - 1))
            logger.info(f"Retrying in {backoff}s...")
            await asyncio.sleep(backoff)
            await _teardown_connection(config.alias)
    await _update_host_status(host_name, HostStatus.ERROR, last_error=last_error)
    return f"[failed after {CONFIG.max_retries} attempts on {host_name}]\nLast error: {last_error}"


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


# ---------------------------------------------------------------------------
# SCP with retry (remote hosts)
# ---------------------------------------------------------------------------

async def _scp_run(
    host_name: str,
    source: str,
    destination: str,
    upload: bool = True,
    timeout: int = CONFIG.ssh_timeout,
) -> str:
    config = _resolve_host(host_name)
    if upload:
        scp_args = ["scp", source, f"{config.alias}:{destination}"]
        action_desc = f"upload {source} -> {host_name}:{destination}"
    else:
        scp_args = ["scp", f"{config.alias}:{source}", destination]
        action_desc = f"download {host_name}:{source} -> {destination}"
    last_error = ""
    for attempt in range(1, CONFIG.max_retries + 1):
        await _ensure_connection(config.alias, host_name)
        rc, stdout, stderr = await _async_run(scp_args, timeout=timeout)
        if rc == 0:
            await _update_host_status(host_name, HostStatus.CONNECTED)
            return f"[OK] {action_desc}"
        if not _is_transient_failure(rc, stderr):
            return f"[scp failed on {host_name}]\n{stderr}"
        last_error = stderr.strip()
        logger.warning(f"{host_name}: scp transient failure (attempt {attempt}/{CONFIG.max_retries}): {last_error}")
        if attempt < CONFIG.max_retries:
            backoff = CONFIG.retry_backoff_base * (2 ** (attempt - 1))
            await asyncio.sleep(backoff)
            await _teardown_connection(config.alias)
    await _update_host_status(host_name, HostStatus.ERROR, last_error=last_error)
    return f"[scp failed after {CONFIG.max_retries} attempts on {host_name}]\n{last_error}"


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def maestro_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    logger.info("maestro: warming up connections...")
    results = await warmup_all_hosts()
    connected = sum(1 for v in results.values() if v)
    total = len(results)
    logger.info(f"maestro: {connected}/{total} hosts connected")
    try:
        yield {"hosts": HOSTS, "warmup_results": results}
    finally:
        try:
            logger.info("maestro: shutting down, closing connections...")
            await teardown_all_hosts()
        except Exception:
            logger.exception("maestro: error during teardown")


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
    # Disable DNS rebinding protection — we're behind Cloudflare Tunnel,
    # so the Host header is the public domain, not localhost.
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    instructions=_build_instructions(),
    # NOTE: No per-session lifespan — SSH lifecycle is managed at the server
    # level by _serve_with_maestro_lifecycle(). A per-session lifespan would
    # tear down ALL SSH ControlMasters when any single session disconnects,
    # breaking other sessions and requiring re-warmup.
)


@mcp.custom_route("/approve", methods=["GET", "POST"])
async def _approve_route(request: Request) -> Response:
    """Consent page + PIN gate for non-Claude.ai OAuth clients."""
    return await _oauth_provider.handle_approve(request)


# --- FILE TRANSFER RELAY ---
# Zero-context-cost file push/pull for sandboxed agents (e.g. Claude.ai).
# Bytes flow over HTTP, never entering the LLM context window.
#
# Auth: Bearer token from MAESTRO_TRANSFER_TOKEN env var (constant-time comparison).
#
#   POST /transfer/push?host=<host>&remote_path=<path>  (multipart upload)
#   GET  /transfer/pull?host=<host>&remote_path=<path>  (file download)
# ---------------------------------------------------------------------------

# Allowed base directories for transfer endpoints (path traversal prevention).
_TRANSFER_ALLOWED_DIRS: list[Path] = [
    Path(d.strip()).expanduser().resolve()
    for d in CONFIG.transfer_allowed_dirs_raw.split(",") if d.strip()
]

# System directories always blocked unless explicitly in the allowlist.
_SYSTEM_DIRS = frozenset({
    "/etc", "/proc", "/sys", "/dev", "/boot", "/sbin", "/bin", "/usr", "/lib", "/var",
})


def _validate_transfer_path(remote_path: str, is_local: bool) -> str | None:
    """Validate a transfer path. Returns an error message if invalid, None if OK."""
    if not remote_path or not remote_path.strip():
        return "remote_path is empty"

    # Reject .. components (applies to both local and remote)
    path_parts = Path(remote_path).parts
    if ".." in path_parts:
        return "path contains '..' components"

    if is_local:
        resolved = Path(remote_path).expanduser().resolve()
        # Check against allowed directories
        if not any(
            resolved == allowed or resolved.is_relative_to(allowed)
            for allowed in _TRANSFER_ALLOWED_DIRS
        ):
            return f"path is outside allowed directories"
        # Block system directories (unless they're within an allowed dir)
        for sys_dir in _SYSTEM_DIRS:
            sys_path = Path(sys_dir).resolve()
            if resolved == sys_path or resolved.is_relative_to(sys_path):
                # Only block if no allowed dir is at or under this system dir
                if not any(
                    allowed == sys_path or allowed.is_relative_to(sys_path)
                    for allowed in _TRANSFER_ALLOWED_DIRS
                ):
                    return f"path resolves to a protected system directory"
    else:
        # Remote host: can't resolve, so be conservative
        expanded = remote_path.replace("~", "/home/_placeholder_")
        resolved_str = str(Path(expanded).resolve())
        for sys_dir in _SYSTEM_DIRS:
            if resolved_str == sys_dir or resolved_str.startswith(sys_dir + "/"):
                if not any(
                    str(allowed).startswith(sys_dir)
                    for allowed in _TRANSFER_ALLOWED_DIRS
                ):
                    return f"path targets a protected system directory"

    return None


def _transfer_auth_ok(request: Request) -> bool:
    """Validate Bearer token for transfer endpoints (constant-time)."""
    if not CONFIG.transfer_token:
        return False
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    return hmac.compare_digest(auth[7:], CONFIG.transfer_token)


def _auth_error() -> JSONResponse:
    return JSONResponse(
        {"error": "unauthorized", "detail": "valid Bearer token required"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


@mcp.custom_route("/transfer/push", methods=["POST"])
async def _transfer_push(request: Request) -> Response:
    """Receive a file upload and write it to the target host."""
    if not _transfer_auth_ok(request):
        return _auth_error()

    host = request.query_params.get("host")
    remote_path = request.query_params.get("remote_path")
    if not host or not remote_path:
        return JSONResponse(
            {"error": "bad_request", "detail": "host and remote_path query params required"},
            status_code=400,
        )

    try:
        config = _resolve_host(host)
    except Exception as e:
        return JSONResponse({"error": "bad_request", "detail": str(e)}, status_code=400)

    # Path sanitization
    path_err = _validate_transfer_path(remote_path, config.is_local)
    if path_err:
        _audit("transfer_push_rejected", host=host, path=remote_path, reason=path_err)
        return JSONResponse(
            {"error": "forbidden", "detail": f"path rejected: {path_err}"},
            status_code=403,
        )

    form = await request.form()
    uploaded = form.get("file")
    if uploaded is None:
        return JSONResponse(
            {"error": "bad_request", "detail": "multipart 'file' field required"},
            status_code=400,
        )

    content_bytes = await uploaded.read()
    if len(content_bytes) > CONFIG.max_transfer_size:
        return JSONResponse(
            {"error": "too_large", "detail": f"file exceeds {CONFIG.max_transfer_size // (1024*1024)}MB limit"},
            status_code=413,
        )

    if config.is_local:
        try:
            p = Path(remote_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content_bytes)
            _audit("transfer_push_ok", host=host, path=remote_path, bytes=len(content_bytes))
            logger.info(f"transfer/push: {len(content_bytes)} bytes -> {host}:{remote_path}")
            return JSONResponse({
                "status": "ok", "host": host,
                "path": remote_path, "bytes": len(content_bytes),
            })
        except Exception as e:
            return JSONResponse({"error": "write_failed", "detail": str(e)}, status_code=500)
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(remote_path).suffix) as tmp:
            tmp.write(content_bytes)
            tmp_path = tmp.name
        try:
            result = await _scp_run(host, tmp_path, remote_path, upload=True)
            if result.startswith("[OK]"):
                _audit("transfer_push_ok", host=host, path=remote_path, bytes=len(content_bytes))
                logger.info(f"transfer/push: {len(content_bytes)} bytes -> {host}:{remote_path} (scp)")
                return JSONResponse({
                    "status": "ok", "host": host,
                    "path": remote_path, "bytes": len(content_bytes),
                })
            else:
                return JSONResponse({"error": "scp_failed", "detail": result}, status_code=502)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


@mcp.custom_route("/transfer/pull", methods=["GET"])
async def _transfer_pull(request: Request) -> Response:
    """Stream a file from the target host back to the caller."""
    if not _transfer_auth_ok(request):
        return _auth_error()

    host = request.query_params.get("host")
    remote_path = request.query_params.get("remote_path")
    if not host or not remote_path:
        return JSONResponse(
            {"error": "bad_request", "detail": "host and remote_path query params required"},
            status_code=400,
        )

    try:
        config = _resolve_host(host)
    except Exception as e:
        return JSONResponse({"error": "bad_request", "detail": str(e)}, status_code=400)

    # Path sanitization
    path_err = _validate_transfer_path(remote_path, config.is_local)
    if path_err:
        _audit("transfer_pull_rejected", host=host, path=remote_path, reason=path_err)
        return JSONResponse(
            {"error": "forbidden", "detail": f"path rejected: {path_err}"},
            status_code=403,
        )

    if config.is_local:
        p = Path(remote_path)
        if not p.is_file():
            return JSONResponse(
                {"error": "not_found", "detail": f"{remote_path} not found"},
                status_code=404,
            )
        if p.stat().st_size > CONFIG.max_transfer_size:
            return JSONResponse(
                {"error": "too_large", "detail": f"file exceeds {CONFIG.max_transfer_size // (1024*1024)}MB limit"},
                status_code=413,
            )
        _audit("transfer_pull_ok", host=host, path=remote_path)
        logger.info(f"transfer/pull: {host}:{remote_path} -> caller")
        return FileResponse(remote_path, filename=p.name, media_type="application/octet-stream")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(remote_path).suffix) as tmp:
            tmp_path = tmp.name
        try:
            result = await _scp_run(host, remote_path, tmp_path, upload=False)
            if not result.startswith("[OK]"):
                Path(tmp_path).unlink(missing_ok=True)
                return JSONResponse({"error": "scp_failed", "detail": result}, status_code=502)
            if Path(tmp_path).stat().st_size > CONFIG.max_transfer_size:
                Path(tmp_path).unlink(missing_ok=True)
                return JSONResponse(
                    {"error": "too_large", "detail": f"file exceeds {CONFIG.max_transfer_size // (1024*1024)}MB limit"},
                    status_code=413,
                )
            _audit("transfer_pull_ok", host=host, path=remote_path)
            logger.info(f"transfer/pull: {host}:{remote_path} -> caller (scp)")
            return FileResponse(
                tmp_path, filename=Path(remote_path).name,
                media_type="application/octet-stream",
                background=BackgroundTask(lambda: Path(tmp_path).unlink(missing_ok=True)),
            )
        except Exception as e:
            Path(tmp_path).unlink(missing_ok=True)
            return JSONResponse({"error": "pull_failed", "detail": str(e)}, status_code=500)


# --- END FILE TRANSFER RELAY ---

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
            return _local_host_hint("maestro_exec", host) + await _local_run(full_cmd, timeout=timeout, cwd=cwd)
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
            return _local_host_hint("maestro_script", host) + await _local_script(script, timeout=timeout, cwd=cwd, sudo=sudo)
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


# ---------------------------------------------------------------------------
# Background command dispatch — fire-and-forget shell commands
# ---------------------------------------------------------------------------

def _bg_output_dir() -> Path:
    """Ensure bg output directory exists."""
    CONFIG.bg_output_dir.mkdir(parents=True, exist_ok=True)
    return CONFIG.bg_output_dir


def _bg_output_path(task_id: str) -> Path:
    """Generate output file path for a background command."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _bg_output_dir() / f"bg_{ts}_{task_id}.txt"


@mcp.tool()
async def maestro_bg(
    host: str,
    command: str,
    cwd: str | None = None,
    sudo: bool = False,
    timeout: int = CONFIG.bg_default_timeout,
) -> str:
    """Run a shell command in the background. Returns a task_id immediately.

    Use agent_poll(task_id) to check status and get the result.
    Use maestro_bg_log(task_id) to tail the output while still running.

    Best for: docker pull, model downloads, long builds, anything that
    takes more than a few seconds. Prevents tool-call timeouts.

    Args:
        host: Target host (see maestro_status for available hosts)
        command: Shell command to execute
        cwd: Working directory to cd into before running the command
        sudo: If True, prepend sudo (assumes passwordless sudo on target)
        timeout: Max seconds before the background task is killed (default 300)
    """
    config = _resolve_host(host)
    task_id = secrets.token_hex(8)
    output_file = _bg_output_path(task_id)
    now = datetime.now(timezone.utc)

    ts = TaskState(
        task_id=task_id,
        agent="bg",
        host=host,
        prompt=command,
        status="running",
        started_at=now,
        output_file=output_file,
    )
    async with _REGISTRY_LOCK:
        TASK_REGISTRY[task_id] = ts

    async def _run() -> None:
        try:
            if config.is_local:
                full_cmd = command
                if sudo:
                    full_cmd = f"sudo {command}"
                result_text = await _local_run(full_cmd, timeout=timeout, cwd=cwd)
            else:
                full_cmd = _wrap_command(config, command, cwd, sudo)
                result_text = await _ssh_run(host, [full_cmd], timeout=timeout)

            # Save full output to disk
            output_file.write_text(result_text, encoding="utf-8")

            # Build inline result (truncated if needed)
            truncated, was_truncated = _orchestra_truncate(result_text)
            result = {
                "task_id": task_id,
                "host": host,
                "command": command[:200],
                "status": "done",
                "output": truncated,
                "output_file": str(output_file) if was_truncated else None,
            }
            ts.status = "done"
            ts.result_json = json.dumps(result)
        except asyncio.CancelledError:
            ts.status = "failed"
            ts.result_json = json.dumps({
                "task_id": task_id, "host": host, "status": "timeout",
                "error": f"Killed after {timeout}s timeout",
            })
        except Exception as exc:
            logger.exception(f"maestro_bg [{task_id}] failed on {host}")
            ts.status = "failed"
            ts.result_json = json.dumps({
                "task_id": task_id, "host": host, "status": "failed",
                "error": str(exc),
            })
        finally:
            ts.finished_at = datetime.now(timezone.utc)
            ts._done_event.set()

    ts.asyncio_task = asyncio.create_task(_run())
    logger.info(f"maestro_bg on {host} [{task_id}]: {command[:80]}...")

    return json.dumps({
        "task_id": task_id,
        "host": host,
        "status": "running",
    })


@mcp.tool()
async def maestro_bg_log(
    task_id: str,
    tail: int = 50,
) -> str:
    """Read recent output from a background command (running or finished).

    Note: Output is captured after the command completes (SSH collects all
    output before returning). For real-time visibility into long commands,
    have the command write its own log file and read it with maestro_read:
        maestro_bg(host, "docker pull image > /tmp/pull.log 2>&1")
        maestro_read(host, "/tmp/pull.log", tail=20)

    Args:
        task_id: Task ID returned by maestro_bg.
        tail: Number of lines from the end to return (default 50).
    """
    async with _REGISTRY_LOCK:
        ts = TASK_REGISTRY.get(task_id)
    if ts is None:
        return json.dumps({"error": f"Task '{task_id}' not found"})
    if ts.output_file is None or not ts.output_file.exists():
        elapsed = (datetime.now(timezone.utc) - ts.started_at).total_seconds()
        return json.dumps({
            "task_id": task_id,
            "status": ts.status,
            "elapsed_seconds": round(elapsed, 1),
            "log": "(no output yet — command still running)",
        })
    try:
        lines = ts.output_file.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = lines[-tail:] if len(lines) > tail else lines
        return json.dumps({
            "task_id": task_id,
            "status": ts.status,
            "total_lines": len(lines),
            "showing_last": len(selected),
            "log": "\n".join(selected),
        })
    except Exception as exc:
        return json.dumps({"error": str(exc), "task_id": task_id})


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
        return _local_host_hint("maestro_read", host) + _local_read_file(path, head=head, tail=tail)
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
        return _local_host_hint("maestro_write", host) + _local_write_file(path, content, append=append, sudo=sudo)
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
        return _local_host_hint("maestro_upload", host) + _local_copy(local_path, remote_path, upload=True)
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
        return _local_host_hint("maestro_download", host) + _local_copy(remote_path, local_path, upload=False)
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
#
# Higher-level tools that dispatch tasks to Codex CLI and Gemini CLI.
# Claude acts as stateful coordinator; these CLIs are stateless executors.
#
# Design principles:
#   - Output discipline: full output saved to disk, structured summary returned
#   - Fat prompt in, structured result out (CLIs are stateless)
#   - Scope discipline: tight, bounded prompts for Codex
#   - File-mediated handoffs: large outputs on disk, read selectively
# ---------------------------------------------------------------------------

# Auto-promote: if a tool call doesn't finish within CONFIG.block_timeout_default
# seconds, it's promoted to a background task and returns a task_id instead
# of blocking the conversation. The subprocess keeps running up to its
# full timeout. Use agent_poll(task_id, wait=N) to long-poll the result.


@dataclass
class TaskState:
    task_id: str
    agent: str            # "codex" | "gemini" | "claude" | "exec" | "script" | "bg"
    host: str
    prompt: str
    status: str           # "running" | "done" | "failed" | "timeout"
    started_at: datetime
    finished_at: datetime | None = None
    asyncio_task: asyncio.Task | None = None
    output_file: Path | None = None
    result_json: str | None = None
    _done_event: asyncio.Event = field(default_factory=asyncio.Event)


TASK_REGISTRY: dict[str, TaskState] = {}
_REGISTRY_LOCK = asyncio.Lock()
_EVICTION_TASK: asyncio.Task | None = None


async def _evict_stale_tasks() -> None:
    """Remove completed tasks older than CONFIG.task_eviction_seconds from registry.

    Cancels any lingering asyncio tasks and cleans up old output files.
    """
    now = datetime.now(timezone.utc)
    async with _REGISTRY_LOCK:
        stale = [
            tid for tid, ts in TASK_REGISTRY.items()
            if ts.finished_at and (now - ts.finished_at).total_seconds() > CONFIG.task_eviction_seconds
        ]
        for tid in stale:
            ts = TASK_REGISTRY.pop(tid)
            # Cancel lingering asyncio task (should already be done, but be safe)
            if ts.asyncio_task and not ts.asyncio_task.done():
                ts.asyncio_task.cancel()
            # Delete output files older than retention period
            if ts.output_file and ts.output_file.exists():
                try:
                    age = (now - ts.started_at).total_seconds()
                    if age > CONFIG.task_output_retention_seconds:
                        ts.output_file.unlink()
                except OSError:
                    pass
    if stale:
        logger.info(f"Orchestra: evicted {len(stale)} stale tasks from registry")


async def _periodic_eviction() -> None:
    """Background loop that evicts stale tasks every 10 minutes."""
    while True:
        await asyncio.sleep(600)
        try:
            await _evict_stale_tasks()
        except Exception:
            logger.exception("Orchestra: periodic eviction failed")


def _orchestra_output_dir() -> Path:
    """Ensure orchestra output directory exists."""
    CONFIG.orchestra_output_dir.mkdir(parents=True, exist_ok=True)
    return CONFIG.orchestra_output_dir


def _orchestra_output_path(agent: str, task_id: str) -> Path:
    """Generate a unique output file path for a CLI invocation."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _orchestra_output_dir() / f"{agent}_{ts}_{task_id}.txt"


def _orchestra_task_id(prompt: str) -> str:
    """Short hash of prompt for file naming."""
    return hashlib.sha256(prompt.encode()).hexdigest()[:8]


def _orchestra_truncate(text: str, max_len: int = CONFIG.max_inline_output) -> tuple[str, bool]:
    """Truncate text, return (text, was_truncated)."""
    if len(text) <= max_len:
        return text, False
    return text[:max_len] + "\n... [truncated]", True


def _extract_gemini_response(raw_output: str) -> str:
    """Extract response text from Gemini CLI JSON envelope.

    Parses the JSON output, extracts the 'response' field, and appends
    token usage summary if stats are available.
    """
    try:
        parsed = json.loads(raw_output)
        if "response" not in parsed:
            return raw_output
        extracted = parsed["response"]
        if "stats" in parsed:
            models_info = parsed["stats"].get("models", {})
            token_summary = {
                m: {
                    "prompt": d.get("tokens", {}).get("prompt", 0),
                    "output": d.get("tokens", {}).get("candidates", 0),
                }
                for m, d in models_info.items()
            }
            extracted += f"\n\n[Tokens: {json.dumps(token_summary)}]"
        return extracted
    except (json.JSONDecodeError, KeyError, TypeError):
        return raw_output


def _orchestra_build_result(
    agent: str,
    host: str,
    prompt: str,
    raw_output: str,
    return_code: int,
    output_file: Path,
) -> str:
    """
    Build structured result. Full output saved to disk, summary returned inline.
    This is the key output-discipline mechanism.
    """
    output_file.write_text(
        f"=== AGENT: {agent} | HOST: {host} ===\n"
        f"=== PROMPT ===\n{prompt}\n\n"
        f"=== OUTPUT ===\n{raw_output}\n",
        encoding="utf-8",
    )

    preview, was_truncated = _orchestra_truncate(raw_output)
    success = return_code == 0

    result = {
        "agent": agent,
        "host": host,
        "success": success,
        "return_code": return_code,
        "output_file": str(output_file),
        "output_preview": preview,
        "truncated": was_truncated,
        "output_bytes": len(raw_output),
    }
    return json.dumps(result, indent=2, ensure_ascii=False)


async def _orchestra_run_cli_raw(
    host: str,
    cli_command: str,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int, str, str]:
    """Run a CLI command and return structured (rc, stdout, stderr).

    Bypasses the text-formatting layer to give callers access to the actual
    return code, avoiding regex re-parsing of formatted output.
    """
    config = _resolve_host(host)

    if config.is_local:
        shell_cmd = cli_command
        if cwd:
            shell_cmd = f"cd {shlex.quote(cwd)} && {cli_command}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
            return (
                proc.returncode or 0,
                stdout_b.decode(errors="replace"),
                stderr_b.decode(errors="replace"),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, "", f"timeout after {timeout}s"
        except FileNotFoundError as e:
            return -1, "", f"binary not found: {e}"
    else:
        full_cmd = _wrap_command(config, cli_command, cwd, sudo=False)
        last_stderr = ""
        for attempt in range(1, CONFIG.max_retries + 1):
            await _ensure_connection(config.alias, host)
            rc, stdout, stderr = await _async_run(
                ["ssh", config.alias, full_cmd], timeout=timeout,
            )
            if not _is_transient_failure(rc, stderr):
                if rc not in (-1, 255):
                    await _update_host_status(host, HostStatus.CONNECTED)
                elif stderr:
                    await _update_host_status(host, HostStatus.ERROR, last_error=stderr.strip())
                return rc, stdout, stderr
            last_stderr = stderr.strip()
            if attempt < CONFIG.max_retries:
                backoff = CONFIG.retry_backoff_base * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)
                await _teardown_connection(config.alias)
        await _update_host_status(host, HostStatus.ERROR, last_error=last_stderr)
        return -1, "", f"failed after {CONFIG.max_retries} attempts: {last_stderr}"


async def _orchestra_run_cli(
    host: str,
    cli_command: str,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int, str]:
    """Run a CLI command, returning (rc, formatted_output).

    Delegates to _orchestra_run_cli_raw for structured execution,
    then formats the output for inline display.
    """
    rc, stdout, stderr = await _orchestra_run_cli_raw(host, cli_command, timeout, cwd)
    combined = _format_result(stdout, stderr, rc)
    return rc, combined


# ---------------------------------------------------------------------------
# Auto-promote: adaptive inline → background execution
# ---------------------------------------------------------------------------

async def _auto_promote(
    execute_fn: Callable[[], Awaitable[str]],
    *,
    block_timeout: int,
    agent: str,
    host: str,
    prompt: str,
) -> str:
    """Run execute_fn with adaptive blocking.

    Tries to return the result inline. If block_timeout elapses before the
    work completes, promotes the task to the background registry and returns
    a task_id immediately.

    Semantics of block_timeout:
      > 0  — wait this many seconds inline, then auto-promote
      == 0 — dispatch immediately (never block)
      < 0  — block forever (legacy behaviour, no promotion)

    Uses asyncio.shield() so that when block_timeout fires, the inner task
    keeps running — we stop waiting, but the subprocess doesn't stop.
    """
    task_id = secrets.token_hex(8)
    started_at = datetime.now(timezone.utc)

    # Start work immediately as an asyncio task
    work_task = asyncio.create_task(execute_fn())

    # --- Full-blocking mode (legacy) ---
    if block_timeout < 0:
        return await work_task

    # --- Try inline execution within block_timeout ---
    if block_timeout > 0:
        try:
            result = await asyncio.wait_for(
                asyncio.shield(work_task),
                timeout=block_timeout,
            )
            return result  # Finished inline — no registry overhead
        except asyncio.TimeoutError:
            pass  # Fall through to auto-promote

    # --- Auto-promote: register as background task ---
    ts = TaskState(
        task_id=task_id,
        agent=agent,
        host=host,
        prompt=prompt[:200],
        status="running",
        started_at=started_at,
        asyncio_task=work_task,
    )

    async def _monitor() -> None:
        try:
            result = await work_task
            ts.status = "done"
            ts.result_json = result
        except asyncio.CancelledError:
            ts.status = "failed"
            ts.result_json = json.dumps({
                "error": "cancelled", "task_id": task_id, "agent": agent,
            })
        except Exception as exc:
            logger.exception(f"auto_promote [{task_id}] {agent} on {host} failed")
            ts.status = "failed"
            ts.result_json = json.dumps({
                "error": str(exc), "task_id": task_id, "agent": agent,
            })
        finally:
            ts.finished_at = datetime.now(timezone.utc)
            ts._done_event.set()

    asyncio.create_task(_monitor())

    async with _REGISTRY_LOCK:
        TASK_REGISTRY[task_id] = ts

    elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
    logger.info(f"auto_promote: {agent} on {host} [{task_id}] promoted after {elapsed:.1f}s")
    return json.dumps({
        "auto_promoted": True,
        "task_id": task_id,
        "agent": agent,
        "host": host,
        "status": "running",
        "elapsed_seconds": round(elapsed, 1),
    })


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

    Codex runs unsandboxed (bypasses workspace-write sandbox that deadlocks
    Rust/Tokio runtimes like LanceDB). It can read files, edit code, run
    commands, and execute tests. Best for: feature implementation,
    refactoring, bug fixes, test generation.

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
    yolo: bool = False,
    timeout: int = CONFIG.gemini_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch an analysis task to Google Gemini CLI on a Maestro host.

    Gemini 3.1 Pro runs in headless mode (read-only by default) with high
    thinking level (Deep Think Mini) enabled by default. Best for:
    large-context codebase analysis, architectural review, document
    comparison, pattern identification across many files.

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The analytical question or task.
        context_files: File paths to include via @file syntax (leverages 1M context).
        working_dir: Working directory for the invocation.
        model: Gemini model (empty=default).
        yolo: Enable write mode (default False = read-only, safer).
        timeout: Max seconds to wait (default 600).
        block_timeout: Inline wait before auto-promote (default 20). 0=dispatch immediately.
    """
    task_id = _orchestra_task_id(prompt)
    output_file = _orchestra_output_path("gemini", task_id)

    async def _execute() -> str:
        full_prompt = prompt
        if context_files:
            file_refs = " ".join(f"@{f}" for f in context_files)
            full_prompt = f"{file_refs} {prompt}"
        escaped_prompt = shlex.quote(full_prompt)
        model_flag = f"--model {shlex.quote(model)} " if model else ""
        yolo_flag = "--yolo " if yolo else ""
        cli_cmd = f"gemini -p {escaped_prompt} --output-format json {model_flag}{yolo_flag}"
        logger.info(f"Orchestra: gemini_analyze on {host} [{task_id}]: {prompt[:80]}...")
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
async def gemini_research(
    host: str,
    query: str,
    timeout: int = CONFIG.gemini_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch a web research task to Gemini CLI with Google Search grounding.

    Gemini 3.1 Pro defaults to high thinking level (Deep Think Mini).
    Best for: jurisprudencia research, technical documentation lookup,
    current events, regulatory changes.

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        query: Research query (Gemini uses Google Search grounding).
        timeout: Max seconds to wait (default 600).
        block_timeout: Inline wait before auto-promote (default 20).
    """
    task_id = _orchestra_task_id(query)
    output_file = _orchestra_output_path("gemini_research", task_id)

    async def _execute() -> str:
        research_prompt = (
            f"Research the following topic thoroughly using web search. "
            f"Provide a comprehensive answer with sources.\n\n{query}"
        )
        escaped = shlex.quote(research_prompt)
        cli_cmd = f"gemini -p {escaped} --output-format json"
        logger.info(f"Orchestra: gemini_research on {host} [{task_id}]: {query[:80]}...")
        rc, raw_output = await _orchestra_run_cli(host, cli_cmd, timeout=timeout)
        return _orchestra_build_result("gemini", host, query, _extract_gemini_response(raw_output), rc, output_file)

    return await _auto_promote(
        _execute,
        block_timeout=block_timeout,
        agent="gemini",
        host=host,
        prompt=query,
    )


@mcp.tool()
async def gemini_execute(
    host: str,
    prompt: str,
    context_files: list[str] | None = None,
    working_dir: str = CONFIG.default_repo,
    model: str = "",
    timeout: int = CONFIG.gemini_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch a coding task to Google Gemini CLI on a Maestro host.

    Gemini 3.1 Pro runs in write mode (--yolo) with high thinking level
    (Deep Think Mini) enabled by default. Best for: code generation,
    refactoring, bug fixes, and implementation tasks that benefit from
    Gemini's 1M-token context window across many files.

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The coding task. Be specific and scoped.
        context_files: File paths to include via @file syntax (leverages 1M context).
        working_dir: Git repo directory where Gemini works.
        model: Gemini model (empty=default).
        timeout: Max seconds to wait (default 600).
        block_timeout: Inline wait before auto-promote (default 20). 0=dispatch immediately.
    """
    task_id = _orchestra_task_id(prompt)
    output_file = _orchestra_output_path("gemini", task_id)

    async def _execute() -> str:
        full_prompt = prompt
        if context_files:
            file_refs = " ".join(f"@{f}" for f in context_files)
            full_prompt = f"{file_refs} {prompt}"
        escaped_prompt = shlex.quote(full_prompt)
        model_flag = f"--model {shlex.quote(model)} " if model else ""
        cli_cmd = f"gemini -p {escaped_prompt} --output-format json {model_flag}--yolo"
        logger.info(f"Orchestra: gemini_execute on {host} [{task_id}]: {prompt[:80]}...")
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
    max_budget_usd: float = 1.0,
    allowed_tools: str = "Edit,Write,Bash(git:*),Read",
    timeout: int = CONFIG.claude_timeout,
    block_timeout: int = CONFIG.block_timeout_default,
) -> str:
    """Dispatch a coding task to Claude Code CLI on a Maestro host.

    Claude Code runs in bypassPermissions mode with a dollar-budget cap.
    Best for: multi-file refactoring, architectural changes, CLAUDE.md-aware
    tasks, and anything requiring strong reasoning over large codebases.

    Full output is saved to disk; a structured summary is returned.
    Auto-promotes to background after block_timeout seconds.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The coding task. Be specific and scoped.
        working_dir: Git repo directory where Claude Code works (reads CLAUDE.md here).
        max_budget_usd: Dollar cap per invocation (default $1.00).
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
            f"--allowedTools {escaped_tools} "
            f"--max-budget-usd {max_budget_usd}"
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
async def codex_dispatch(
    host: str,
    prompt: str,
    working_dir: str = CONFIG.default_repo,
    model: str = "",
    reasoning_effort: str = "xhigh",
    timeout: int = CONFIG.codex_timeout,
) -> str:
    """Dispatch a coding task to Codex CLI asynchronously. Returns a task_id immediately.

    Use agent_poll(task_id) to check progress and retrieve the result.
    Best for long-running tasks where you don't want to block.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The coding task. Be specific and scoped.
        working_dir: Git repo directory where Codex works.
        model: Codex model (empty=default, 'gpt-5.3-codex').
        reasoning_effort: Thinking effort level ('low', 'medium', 'high', 'xhigh'). Default 'xhigh'.
        timeout: Max seconds for the background task (default 300).
    """
    return await codex_execute(
        host=host, prompt=prompt, working_dir=working_dir,
        model=model, reasoning_effort=reasoning_effort,
        timeout=timeout, block_timeout=0,
    )


@mcp.tool()
async def gemini_dispatch(
    host: str,
    prompt: str,
    context_files: list[str] | None = None,
    working_dir: str = CONFIG.default_repo,
    model: str = "",
    yolo: bool = False,
    timeout: int = CONFIG.gemini_timeout,
) -> str:
    """Dispatch an analysis task to Gemini CLI asynchronously. Returns a task_id immediately.

    Gemini 3.1 Pro defaults to high thinking level (Deep Think Mini).
    Use agent_poll(task_id) to check progress and retrieve the result.
    Best for large-context analysis where you don't want to block.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The analytical question or task.
        context_files: File paths to include via @file syntax.
        working_dir: Working directory for the invocation.
        model: Gemini model (empty=default).
        yolo: Enable write mode (default False = read-only).
        timeout: Max seconds for the background task (default 180).
    """
    return await gemini_analyze(
        host=host, prompt=prompt, context_files=context_files,
        working_dir=working_dir, model=model, yolo=yolo,
        timeout=timeout, block_timeout=0,
    )


@mcp.tool()
async def claude_dispatch(
    host: str,
    prompt: str,
    working_dir: str = CONFIG.default_repo,
    max_budget_usd: float = 1.0,
    allowed_tools: str = "Edit,Write,Bash(git:*),Read",
    timeout: int = CONFIG.claude_timeout,
) -> str:
    """Dispatch a coding task to Claude Code CLI asynchronously. Returns a task_id immediately.

    Use agent_poll(task_id) to check progress and retrieve the result.
    Best for multi-file refactoring or architectural tasks that take minutes.

    Args:
        host: Target host (see maestro_status for available hosts)
        prompt: The coding task. Be specific and scoped.
        working_dir: Git repo directory where Claude Code works.
        max_budget_usd: Dollar cap per invocation (default $1.00).
        allowed_tools: Comma-separated tool whitelist.
        timeout: Max seconds for the background task (default 300).
    """
    return await claude_execute(
        host=host, prompt=prompt, working_dir=working_dir,
        max_budget_usd=max_budget_usd, allowed_tools=allowed_tools,
        timeout=timeout, block_timeout=0,
    )


@mcp.tool()
async def agent_poll(task_id: str, wait: int = 0) -> str:
    """Check the status of an async agent dispatch task.

    Returns immediately with either the running status + elapsed time,
    or the full structured result if the task has completed.

    Args:
        task_id: Task ID returned by a previous *_dispatch call.
        wait: Max seconds to hold connection waiting for completion (long-poll).
              0 = return immediately (default). >0 = wait up to this many seconds.
    """
    async with _REGISTRY_LOCK:
        ts = TASK_REGISTRY.get(task_id)
    if ts is None:
        return json.dumps({"error": f"Task '{task_id}' not found (completed and evicted, or never existed)"})

    # Long-poll: hold connection until task completes or wait expires
    if ts.status == "running" and wait > 0:
        try:
            await asyncio.wait_for(ts._done_event.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass  # Still running — return current status below

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

        # FastMCP's streamable_http_app() includes all OAuth routes,
        # metadata endpoints, and bearer auth middleware automatically.
        app = mcp.streamable_http_app()

        # OAuth URL rewrite: LAN/localhost clients get metadata matching
        # their connection URL instead of the public MAESTRO_ISSUER_URL.
        from oauth_rewrite import OAuthURLRewriteMiddleware, _parse_lan_origins
        from urllib.parse import urlparse as _urlparse

        # Build allowed origins allowlist
        _parsed_issuer = _urlparse(CONFIG.issuer_url)
        _canonical_host = _parsed_issuer.netloc  # e.g. "maestro.rmstxrx.dev"
        _allowed_origins: dict[str, str] = {
            _canonical_host: CONFIG.issuer_url,
            # Always allow localhost/loopback
            "localhost:8222": "http://localhost:8222",
            "127.0.0.1:8222": "http://127.0.0.1:8222",
        }
        # Add LAN origins from env var
        _lan_env = os.environ.get("MAESTRO_LAN_ORIGINS", "")
        _allowed_origins.update(_parse_lan_origins(_lan_env))
        logger.info("oauth_rewrite allowed_origins: %s", list(_allowed_origins.keys()))

        app = OAuthURLRewriteMiddleware(app, CONFIG.issuer_url, allowed_origins=_allowed_origins)

        # ASGI middleware: request logging + registration rate-limit enforcement
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
            global _EVICTION_TASK
            logger.info("maestro: warming up connections...")
            results = await warmup_all_hosts()
            connected = sum(1 for v in results.values() if v)
            logger.info(f"maestro: {connected}/{len(results)} hosts connected")
            _EVICTION_TASK = asyncio.create_task(_periodic_eviction())
            try:
                await server.serve()
            finally:
                if _EVICTION_TASK:
                    _EVICTION_TASK.cancel()
                try:
                    logger.info("maestro: shutting down, closing connections...")
                    await teardown_all_hosts()
                except Exception:
                    logger.exception("maestro: error during teardown")

        asyncio.run(_serve_with_maestro_lifecycle())
    else:
        mcp.run(transport="stdio")
