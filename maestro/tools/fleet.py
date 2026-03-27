"""Fleet MCP tool functions."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
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
    _local_write_file,
)
from maestro.mux import (
    capture_pane,
    cleanup_task_files,
    create_task_window,
    get_output_path,
    kill_window,
    list_windows,
    send_keys,
    wait_for_completion,
    TMUX_SESSION,
)
from maestro.tools.orchestra import (
    _auto_promote,
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


def _record_io(task_type: str, host: str, prompt: str, status: str = "done") -> None:
    """Record a ledger entry for a synchronous I/O operation (read/write/transfer)."""
    from maestro.tools.orchestra import _record_ledger_entry, get_task_ledger
    from maestro.client import get_client_context
    if get_task_ledger() is None:
        return
    ctx = get_client_context()
    now = datetime.now(timezone.utc)
    task_id = secrets.token_hex(4)
    _record_ledger_entry(
        task_id=task_id,
        agent=task_type,
        host=host,
        prompt=prompt[:200],
        status=status,
        client_class=ctx.classification,
        dispatched_at=now,
        output_file=None,
        task_type=task_type,
    )
    ledger = get_task_ledger()
    if ledger:
        ledger.update(task_id, status="done", completed_at=now)

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
        result = await _ssh_run(host, [cmd], timeout=config.ssh_timeout)
        _record_io("read", host, path)
        return result

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
            result = await _ssh_run(host, [cmd], timeout=timeout, stdin_data=content)
            _record_io("write", host, path)
            return result
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
            result = await _ssh_run(host, [cmd], timeout=timeout, stdin_data=content)
            _record_io("write", host, path)
            return result

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
            result = await _scp_run(host, local_path, remote_path, upload=True)
            _record_io("transfer", host, f"upload {local_path} -> {remote_path}")
            return result
        elif direction == "download":
            if cfg.is_local:
                return _local_copy(remote_path, local_path, upload=False)
            result = await _scp_run(host, remote_path, local_path, upload=False)
            _record_io("transfer", host, f"download {remote_path} -> {local_path}")
            return result
        else:
            return json.dumps({"error": f"Invalid direction '{direction}'. Use 'upload' or 'download'."})

    @mcp.tool()
    async def status(host: str = "", agents: bool = False) -> str:
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
    async def observe(task_id: str, lines: int = 50) -> str:
        """Capture live output from a running task's tmux pane (ADR-0007).

        Local pane read — zero SSH cost, instant response.
        Works on any task: run, dispatch, service, interactive.
        Use to monitor agent progress, check command output, or
        verify a service is running.

        Returns the last N lines of visible pane content."""
        try:
            content = await capture_pane(task_id, lines)
            return json.dumps({
                "task_id": task_id,
                "lines": lines,
                "content": content,
            })
        except RuntimeError as e:
            return json.dumps({"error": str(e), "task_id": task_id})

    @mcp.tool()
    async def steer(task_id: str, keys: str) -> str:
        """Send input to a running task's tmux pane (ADR-0007).

        Keystrokes are sent locally and relayed through SSH to the remote process.
        Everything sent is logged to the task's output file (audit trail).

        Use to: course-correct an agent, answer a prompt, send Ctrl-C (use 'C-c'),
        type Enter (use 'Enter'), or drive an interactive agent session.

        Special keys: Enter, C-c (Ctrl+C), C-d (Ctrl+D), Escape, Tab."""
        try:
            await send_keys(task_id, keys)

            # Log the steering input to the output file for audit trail
            from maestro.mux import get_output_path
            output_file = get_output_path(task_id)
            if output_file.exists():
                with open(output_file, "a") as f:
                    f.write(f"\n[STEER] {keys}\n")

            return json.dumps({
                "task_id": task_id,
                "sent": keys,
                "logged": True,
            })
        except RuntimeError as e:
            return json.dumps({"error": str(e), "task_id": task_id})

    @mcp.tool()
    async def stop(task_id: str) -> str:
        """Kill a running task (ADR-0007).

        Kills the Cellar-local tmux window. The SSH session inside it dies,
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
            await kill_window(task_id)

            # Update ledger
            from maestro.tools.orchestra import get_task_ledger
            ledger = get_task_ledger()
            if ledger:
                from datetime import datetime, timezone
                ledger.update(task_id, status="killed", completed_at=datetime.now(timezone.utc))

            return json.dumps({
                "task_id": task_id,
                "status": "killed",
                "window": window_name,
            })
        except RuntimeError as e:
            return json.dumps({"error": str(e), "task_id": task_id})

    @mcp.tool()
    async def service(
        host: str,
        command: str,
        label: str = "",
        cwd: str | None = None,
        capture: bool = False,
    ) -> str:
        """Start a long-running process on a host (ADR-0007).

        For services like vLLM, Jupyter, training runs, or any process
        that runs indefinitely. No hard ceiling — runs until stopped.

        The service is observable via observe(task_id) for live pane output
        and steerable via steer(task_id). Stop with stop(task_id).

        capture: if True, tee output to disk (caution: service logs grow).
        Default is False — rely on observe for live reads.

        Overtime advisory at 24h (configurable). This is informational, not
        a kill signal.

        Returns immediately with {task_id} — always background."""
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        task_id = secrets.token_hex(8)
        ctx = get_client_context()

        await create_task_window(
            task_id,
            cfg.alias,
            command,
            tee=capture,
            interactive=False,
            cwd=cwd,
            shell=cfg.shell.value,
        )

        # Record in ledger
        from maestro.tools.orchestra import _record_ledger_entry
        from datetime import datetime, timezone as tz
        _record_ledger_entry(
            task_id=task_id,
            agent="service",
            host=host,
            prompt=(label or command[:200]),
            status="running",
            client_class=ctx.classification,
            dispatched_at=datetime.now(tz.utc),
            output_file=get_output_path(task_id) if capture else None,
            expected_runtime=config.service_overtime_advisory,
            task_type="service",
        )

        return json.dumps({
            "task_id": task_id,
            "host": host,
            "label": label or command[:80],
            "capture": capture,
            "hint": "Use observe(task_id) for live output, stop(task_id) to kill.",
        })
