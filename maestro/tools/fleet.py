"""Fleet MCP tool functions."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from maestro.client import get_client_context
from maestro.config import MaestroConfig
from maestro.hosts import (
    HOSTS,
    HostConfig,
    HostStatus,
    _resolve_host,
    _update_host_status,
)
from maestro.mux import (
    create_task_window,
    get_output_path,
    kill_window,
    list_windows,
    send_keys,
    stage_script,
    wait_for_completion,
    TMUX_SESSION,
)
from maestro.tools.orchestra import (
    TASK_REGISTRY,
    _REGISTRY_LOCK,
    _auto_promote,
    _orchestra_run_cli,
    _orchestra_truncate,
    _save_registry,
)
from maestro.relay import transfer_pull_impl
from maestro.transport import (
    _async_run,
    _check_control_master,
    _ensure_connection,
    _is_transient_failure,
    _structured_error,
    _teardown_connection,
    _warmup_connection,
)

logger = logging.getLogger("maestro")


_AGENT_CLI_PATTERNS = re.compile(
    r"^\s*(codex|gemini|claude)\b.*(?:-[pq]|--prompt|--model|--message)(?:\s|=|$)",
    re.IGNORECASE | re.DOTALL,
)

_READ_WRITE_MAX_BYTES = 16384
_READ_WRITE_TIMEOUT = 10


def _shell_quote(s: str) -> str:
    """Single-quote a string for safe use in shell commands."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


async def _raw_ssh(host: str, cmd: str, timeout: int, stdin_data: str | None = None) -> tuple[int, str, str]:
    """Run a single SSH command and return raw (rc, stdout, stderr).

    Includes connection-ensure and one retry on transient failure.
    Does NOT format the result — caller gets raw streams.
    """
    from maestro.hosts import _resolve_host as resolve_host

    cfg = resolve_host(host)
    rc, stdout, stderr = 0, "", ""
    for attempt in (1, 2):
        await _ensure_connection(cfg.alias, host)
        rc, stdout, stderr = await _async_run(
            ["ssh", cfg.alias, cmd],
            timeout=timeout,
            stdin_data=stdin_data,
        )
        if not _is_transient_failure(rc, stderr):
            return rc, stdout, stderr
        if attempt < 2:
            logger.warning(f"read/write {host}: transient failure, retrying: {stderr.strip()}")
            await _teardown_connection(cfg.alias)
            await asyncio.sleep(0.5)
    return rc, stdout, stderr


def _check_local_self_reference(host: str) -> str | None:
    """Block stdio clients from targeting the local host with fleet I/O tools.

    Returns an error JSON string if blocked, None if the command should proceed.
    """
    ctx = get_client_context()
    if not hasattr(ctx, "client_type") or ctx.client_type != "stdio":
        return None
    try:
        cfg = _resolve_host(host)
    except Exception:
        return None  # let the tool handle the unknown host error
    if not getattr(cfg, "is_local", False):
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
        "recommended_tool": "dispatch_agent",
        "message": (
            f"Detected a raw {agent} CLI dispatch with prompt/model flags. "
            "Use dispatch_agent instead so Maestro applies the scope prefix, "
            "records the task in the ledger, and builds the correct CLI arguments."
        ),
    })




def register_fleet_tools(mcp: object, config: MaestroConfig) -> None:
    """Register fleet tools on the given FastMCP instance."""

    from mcp.server.fastmcp import FastMCP
    assert isinstance(mcp, FastMCP)

    # --- Fleet tools ---

    # --- ADR-0009: unified task execution via run_task ---

    @mcp.tool()
    async def run_task(
        host: str,
        task_id: str = "",
        command: str = "",
        cwd: str | None = None,
        expected_runtime: int | None = None,
        sudo: bool = False,
        persistent: bool = False,
        capture: bool = False,
        label: str = "",
    ) -> str:
        """Execute a command or staged script on a fleet host via tmux.

        Provide exactly one of command or task_id.
        command= stages the script internally before execution.
        task_id= runs a pre-staged script from /tmp/maestro/inbox/.

        Non-persistent tasks try to finish within the client profile's
        block_timeout_exec window, then auto-promote into the task ledger.
        Persistent tasks always return immediately and run until stopped."""
        if block := _check_local_self_reference(host):
            return block
        if not task_id and not command:
            return json.dumps({
                "error": "validation_error",
                "detail": "Provide either task_id (staged) or command.",
            })
        if task_id and command:
            return json.dumps({"error": "validation_error", "detail": "Provide task_id or command, not both."})
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if command:
            if bypass := _check_agent_dispatch_bypass(command):
                return bypass

        ctx = get_client_context()
        effective_task_id = task_id or secrets.token_hex(8)
        block_timeout = 0 if persistent else int(
            ctx.profile.get("block_timeout_exec", config.block_timeout_default)
        )
        tee_output = capture or not persistent
        task_type = "service" if persistent else "run"
        ert = expected_runtime if expected_runtime is not None else (
            config.service_overtime_advisory if persistent else config.default_expected_runtime_run
        )

        async def _execute() -> str:
            if command:
                script_content = f"#!/bin/bash\n{command}\n"
                await stage_script(
                    effective_task_id,
                    cfg.alias,
                    script_content,
                    cfg.shell,
                    is_local=getattr(cfg, "is_local", False),
                )
            await create_task_window(
                effective_task_id,
                cfg.alias,
                tee=tee_output,
                cwd=cwd,
                sudo=sudo,
                stream=True,
                shell=cfg.shell,
                is_local=getattr(cfg, "is_local", False),
            )
            rc = await wait_for_completion(
                effective_task_id,
                timeout=None if persistent else config.run_ceiling,
            )
            result: dict[str, Any] = {
                "task_id": effective_task_id,
                "host": host,
                "return_code": rc,
                "persistent": persistent,
                "capture": tee_output,
            }
            if label:
                result["label"] = label
            if tee_output:
                output_path = get_output_path(effective_task_id)
                raw_output = ""
                if output_path.exists():
                    raw_output = output_path.read_text(encoding="utf-8", errors="replace")
                preview, was_truncated = _orchestra_truncate(raw_output, max_len=config.max_inline_output)
                result["output"] = preview
                result["truncated"] = was_truncated
            return json.dumps(result)

        result = await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="exec",
            host=host,
            prompt=(label or command or effective_task_id)[:200],
            client_class=ctx.classification,
            task_id=effective_task_id,
            expected_runtime=ert,
            output_file_factory=get_output_path if tee_output else None,
            task_type=task_type,
        )
        if not persistent:
            return result

        payload = json.loads(result)
        payload["persistent"] = True
        payload["capture"] = tee_output
        if label:
            payload["label"] = label
        return json.dumps(payload)

    @mcp.tool()
    async def orchestra_status(host: str = "", agents: bool = False) -> str:
        """Fleet health check with auto-reconnect and optional agent discovery (ADR-0007).

        Probes connectivity for all hosts (or a single host if specified).
        Disconnected hosts get a full teardown + reconnect attempt automatically.
        Set agents=True to also check Codex/Gemini/Claude Code CLI availability
        on each connected host.

        Consolidates the old status, reconnect_host, and agent_status tools."""

        async def _check_one(name: str, cfg: HostConfig) -> dict:
            if cfg.is_local:
                await _update_host_status(name, HostStatus.CONNECTED)
                return {"status": "connected", "local": True}
            alive = await _check_control_master(cfg.alias)
            if alive:
                await _update_host_status(name, HostStatus.CONNECTED)
                return {"status": "connected", "local": False}
            # Full reconnect: teardown stale socket, then warmup fresh
            await _teardown_connection(cfg.alias)
            await asyncio.sleep(0.5)
            if await _warmup_connection(cfg.alias):
                await _update_host_status(name, HostStatus.CONNECTED)
                return {"status": "reconnected", "local": False}
            await _update_host_status(name, HostStatus.DISCONNECTED)
            result: dict = {"status": "offline", "local": False}
            if cfg.last_error:
                result["error"] = cfg.last_error
            return result

        async def _check_agents(name: str) -> dict:
            agents_result = {}
            for cli in ("codex", "gemini", "claude"):
                rc, out = await _orchestra_run_cli(name, f"{cli} --version 2>&1", timeout=10)
                agents_result[cli] = {"available": rc == 0, "version": out.strip()[:100] if rc == 0 else None}
            return agents_result

        # Filter to single host if specified
        targets = {}
        if host:
            try:
                cfg = _resolve_host(host)
                targets[host] = cfg
            except ValueError as e:
                return _structured_error("validation_error", host, str(e))
        else:
            targets = dict(HOSTS)

        results = await asyncio.gather(
            *[_check_one(name, cfg) for name, cfg in targets.items()]
        )
        hosts_status = dict(zip(targets.keys(), results))

        # Optionally probe agent CLIs on connected hosts
        if agents:
            connected_names = [
                name for name, r in hosts_status.items()
                if r["status"] in ("connected", "reconnected")
            ]
            if connected_names:
                agent_results = await asyncio.gather(
                    *[_check_agents(name) for name in connected_names]
                )
                for name, ar in zip(connected_names, agent_results):
                    hosts_status[name]["agents"] = ar

        connected = sum(1 for r in hosts_status.values() if r["status"] in ("connected", "reconnected"))
        return json.dumps({
            "hosts": hosts_status,
            "available": connected,
            "total": len(targets),
        })
    # --- ADR-0007: Task lifecycle tools ---

    @mcp.tool()
    async def stop_task(task_id: str, graceful: bool = False) -> str:
        """Kill a running task (ADR-0007).

        Kills the Hub-local tmux window. The SSH session inside it dies,
        which terminates the remote process.

        Safety: refuses to kill the tmux server itself. Only task windows
        can be stopped.

        Updates the task ledger with status='killed'."""
        # Validate task_id format (prevent killing arbitrary windows)
        if not task_id or len(task_id) < 8:
            return json.dumps({"error": "Invalid task_id", "task_id": task_id})

        window_name = f"task-{task_id[:12]}"
        # Safety: refuse to kill the session itself
        if window_name in ("tasks", TMUX_SESSION):
            return json.dumps({"error": "Cannot kill the tmux session", "task_id": task_id})

        try:
            if graceful:
                await send_keys(task_id, "C-c")
                await asyncio.sleep(3)
                windows = await list_windows()
                if any(window.get("name") == window_name for window in windows):
                    await kill_window(task_id)
            else:
                await kill_window(task_id)

            completed_at = datetime.now(timezone.utc)

            async with _REGISTRY_LOCK:
                ts = TASK_REGISTRY.get(task_id)
                if ts is not None:
                    ts.status = "killed"
                    ts.finished_at = completed_at
                    ts.result_json = json.dumps({
                        "task_id": task_id,
                        "agent": ts.agent,
                        "host": ts.host,
                        "status": "killed",
                        "graceful": graceful,
                    })
                    ts._done_event.set()
            _save_registry()

            # Update ledger
            from maestro.tools.orchestra import get_task_ledger
            ledger = get_task_ledger()
            if ledger:
                ledger.update(task_id, status="killed", completed_at=completed_at)

            return json.dumps({
                "task_id": task_id,
                "status": "killed",
                "graceful": graceful,
                "window": window_name,
            })
        except RuntimeError as e:
            return json.dumps({"error": str(e), "task_id": task_id})

    # --- ADR-0007: Direct file I/O (orchestrator only) ---

    @mcp.tool()
    async def read_file(host: str, path: str) -> str:
        """Read a small file from a fleet host (≤16 KB, 10 s timeout).

        Returns file content directly. When the file exceeds 16 KB, returns
        a truncated preview and, if relay staging succeeds, a curl command
        for downloading the full file.

        This is an orchestrator tool — dispatched agents use their
        native filesystem instead."""
        if block := _check_local_self_reference(host):
            return block
        try:
            _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        cmd = f"head -c {_READ_WRITE_MAX_BYTES} -- {_shell_quote(path)} || true"
        rc, stdout, stderr = await _raw_ssh(host, cmd, timeout=_READ_WRITE_TIMEOUT)

        if rc not in (0, 141):  # 141 = SIGPIPE from head, expected for large files
            return json.dumps({
                "error": "read_failed",
                "host": host,
                "path": path,
                "exit_code": rc,
                "stderr": stderr.strip(),
            })

        stdout_bytes = len(stdout.encode())
        truncated = stdout_bytes >= _READ_WRITE_MAX_BYTES
        result = {
            "host": host,
            "path": path,
            "bytes": stdout_bytes,
            "truncated": truncated,
            "content": stdout,
        }
        if truncated:
            try:
                relay_info = await transfer_pull_impl(host, path)
                result["curl"] = relay_info["curl"]
                result["full_bytes"] = relay_info["bytes"]
            except Exception:
                pass  # Relay staging failed — still return the truncated content
            result["hint"] = "Use tail= or head= for targeted reads, or full=True to download the complete file."

        return json.dumps(result)

    @mcp.tool()
    async def write_file(host: str, path: str, content: str) -> str:
        """Write a small file to a fleet host (≤16 KB, 10 s timeout).

        Content is piped via stdin — no shell escaping issues.
        For larger files, use transfer_push_file(host, remote_path).

        This is an orchestrator tool — dispatched agents use their
        native filesystem instead."""
        if block := _check_local_self_reference(host):
            return block
        try:
            _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        content_bytes = len(content.encode())
        if content_bytes > _READ_WRITE_MAX_BYTES:
            return json.dumps({
                "error": "content_too_large",
                "host": host,
                "path": path,
                "bytes": content_bytes,
                "limit": _READ_WRITE_MAX_BYTES,
                "message": (
                    f"Content is {content_bytes} bytes (limit: {_READ_WRITE_MAX_BYTES}). "
                    f"Use the transfer relay instead."
                ),
            })

        parent = str(Path(path).parent)
        cmd = f"mkdir -p -- {_shell_quote(parent)} && cat > {_shell_quote(path)}"
        rc, stdout, stderr = await _raw_ssh(
            host, cmd,
            timeout=_READ_WRITE_TIMEOUT,
            stdin_data=content,
        )

        if rc != 0:
            return json.dumps({
                "error": "write_failed",
                "host": host,
                "path": path,
                "exit_code": rc,
                "stderr": stderr.strip(),
            })

        return json.dumps({
            "host": host,
            "path": path,
            "bytes": content_bytes,
            "status": "ok",
        })
