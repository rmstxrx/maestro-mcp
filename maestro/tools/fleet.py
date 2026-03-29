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
    stage_script,
    wait_for_completion,
    TMUX_SESSION,
)
from maestro.tools.orchestra import (
    _auto_promote,
    _orchestra_run_cli,
)
from maestro.transport import (
    _check_control_master,
    _structured_error,
    _teardown_connection,
    _warmup_connection,
)

logger = logging.getLogger("maestro")


_AGENT_CLI_PATTERNS = re.compile(
    r"^\s*(codex|gemini|claude)\b.*(?:-[pq]|--prompt|--model|--message)(?:\s|=|$)",
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

    # --- ADR-0007: Hub-local execution via exec ---

    @mcp.tool()
    async def exec(
        host: str,
        task_id: str,
        cwd: str | None = None,
        expected_runtime: int | None = None,
        sudo: bool = False,
    ) -> str:
        """Trigger execution of a pre-staged script on a host. The script must already exist at /tmp/maestro/inbox/<task_id>.sh (pushed via relay). Returns task_id for status tracking."""
        if block := _check_local_self_reference(host):
            return block
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        ctx = get_client_context()
        ert = expected_runtime if expected_runtime is not None else config.default_expected_runtime_run

        async def _execute() -> str:
            await create_task_window(
                task_id,
                cfg.alias,
                tee=False,
                cwd=cwd,
                sudo=sudo,
            )
            rc = await wait_for_completion(task_id, timeout=config.run_ceiling)
            return json.dumps({"task_id": task_id, "host": host, "return_code": rc})

        return await _auto_promote(
            _execute,
            block_timeout=0,
            agent="exec",
            host=host,
            prompt=task_id,
            client_class=ctx.classification,
            task_id=task_id,
            expected_runtime=ert,
        )

    @mcp.tool()
    async def gemini_sessions(host: str) -> str:
        """List Gemini CLI sessions on a host."""
        if block := _check_local_self_reference(host):
            return block
        try:
            _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        rc, output = await _orchestra_run_cli(host, "gemini --list-sessions", timeout=15)
        if rc != 0:
            return json.dumps({"host": host, "error": output})
        return json.dumps({"host": host, "sessions": output})


    @mcp.tool()
    async def observe(task_id: str, lines: int = 50) -> str:
        """Capture live output from a running task's tmux pane (~50 lines).

        Control-plane tool for inspecting dispatched agents and services
        mid-run. Returns the current screen state, not cumulative output.
        For bulk output retrieval, use relay-pull of the outbox file."""
        from maestro.mux import capture_pane
        try:
            output = await capture_pane(task_id, lines=lines)
            return json.dumps({"task_id": task_id, "lines": lines, "output": output})
        except RuntimeError as e:
            return json.dumps({"error": str(e), "task_id": task_id})

    @mcp.tool()
    async def steer(task_id: str, keys: str) -> str:
        """Send keystrokes to a running task's tmux pane.

        Control-plane tool for interacting with dispatched agents —
        approval prompts, Ctrl+C (send as 'C-c'), input text.
        Pure control signal, no data payload."""
        from maestro.mux import send_keys
        try:
            await send_keys(task_id, keys)
            return json.dumps({"task_id": task_id, "keys_sent": len(keys), "status": "ok"})
        except RuntimeError as e:
            return json.dumps({"error": str(e), "task_id": task_id})

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
    async def stop(task_id: str) -> str:
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

        The service can be monitored by reading its log file with periodic
        run(host, "tail -50 <log_path>") calls. Stop with stop(task_id).

        capture: if True, tee output to disk (caution: service logs grow).
        Recommended: keep capture=True and monitor via `run`.

        Overtime advisory at 24h (configurable). This is informational, not
        a kill signal.

        Returns immediately with {task_id} — always background."""
        try:
            cfg = _resolve_host(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))

        task_id = secrets.token_hex(8)
        ctx = get_client_context()

        script_content = f"#!/bin/bash\n{command}\n"
        await stage_script(task_id, cfg.alias, script_content)
        await create_task_window(
            task_id,
            cfg.alias,
            tee=capture,
            cwd=cwd,
            stream=True,
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
            "hint": "Read output logs with run(...) for progress, stop(task_id) to kill.",
        })
