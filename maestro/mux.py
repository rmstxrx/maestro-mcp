"""Hub-local tmux multiplexer — ADR-0007.

All task execution runs inside tmux windows on the Hub. Remote commands
are wrapped in SSH sessions inside those windows. Maestro observes, steers,
and detects completion locally — no network crossing required.

Only Maestro creates tmux sessions. Agents never create remote tmux.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from pathlib import Path

logger = logging.getLogger("maestro")

TMUX_SERVER = "maestro"
TMUX_SESSION = "tasks"
OUTPUT_DIR = Path("/root/.maestro/task_output")


def configure_mux(*, output_dir: Path | None = None) -> None:
    """Set the output directory for task captures. Called once at startup."""
    global OUTPUT_DIR
    if output_dir is not None:
        OUTPUT_DIR = output_dir
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


async def _tmux(*args: str, timeout: int = 10) -> str:
    """Run a tmux command against the maestro server. Returns stdout."""
    cmd = ["tmux", "-L", TMUX_SERVER, *args]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"tmux command timed out: {' '.join(cmd)}")
    stdout = stdout_b.decode(errors="replace").rstrip("\n")
    if proc.returncode != 0:
        stderr = stderr_b.decode(errors="replace").rstrip("\n")
        if "no server running" not in stderr and "session not found" not in stderr:
            logger.debug("tmux [rc=%d]: %s — %s", proc.returncode, " ".join(args), stderr)
    return stdout


async def ensure_server() -> None:
    """Ensure the maestro tmux server and task session exist."""
    result = await asyncio.create_subprocess_exec(
        "tmux", "-L", TMUX_SERVER, "has-session", "-t", TMUX_SESSION,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await result.wait()
    if result.returncode != 0:
        await _tmux("new-session", "-d", "-s", TMUX_SESSION)
        logger.info("mux: created tmux server '%s', session '%s'", TMUX_SERVER, TMUX_SESSION)


def _build_wrapper(
    task_id: str,
    ssh_alias: str,
    command: str,
    *,
    tee: bool = True,
    cwd: str | None = None,
    sudo: bool = False,
    shell: str = "bash",
) -> str:
    """Build wrapper script for a single command inside a Hub-local tmux window."""
    output_file = OUTPUT_DIR / f"{task_id}.txt"
    rc_file = OUTPUT_DIR / f"{task_id}.rc"

    # Build the remote command
    if shell == "powershell":
        remote_parts = []
        if cwd:
            remote_parts.append(f"Set-Location -LiteralPath '{cwd}';")
        remote_parts.append(f"sudo {command}" if sudo else command)
        remote_cmd = " ".join(remote_parts)
    else:
        remote_parts = []
        if cwd:
            remote_parts.append(f"cd {shlex.quote(cwd)} &&")
        if sudo:
            remote_parts.append("sudo")
        remote_parts.append(command)
        remote_cmd = " ".join(remote_parts)

    ssh_cmd = f"ssh {shlex.quote(ssh_alias)} {shlex.quote(remote_cmd)}"

    lines = ["#!/bin/bash"]
    if tee:
        lines.append(f"{ssh_cmd} 2>&1 | tee {shlex.quote(str(output_file))}")
        lines.append(f"echo ${{PIPESTATUS[0]}} > {shlex.quote(str(rc_file))}")
    else:
        lines.append(ssh_cmd)
        lines.append(f"echo $? > {shlex.quote(str(rc_file))}")
    lines.append(f"tmux -L {TMUX_SERVER} wait-for -S 'done-{task_id}'")
    return "\n".join(lines)


def _build_script_wrapper(
    task_id: str,
    ssh_alias: str,
    script_body: str,
    *,
    tee: bool = True,
    cwd: str | None = None,
    sudo: bool = False,
    shell: str = "bash",
) -> str:
    """Build wrapper for multi-line scripts piped via stdin."""
    output_file = OUTPUT_DIR / f"{task_id}.txt"
    rc_file = OUTPUT_DIR / f"{task_id}.rc"

    if shell == "powershell":
        script_lines = ["$ErrorActionPreference = 'Stop'"]
        if cwd:
            script_lines.append(f"Set-Location -LiteralPath '{cwd}'")
        script_lines.append(script_body)
        escaped_script = "\n".join(script_lines)
        ssh_cmd = f"ssh {shlex.quote(ssh_alias)} 'powershell -Command -'"
    else:
        script_lines = ["set -euo pipefail"]
        if cwd:
            script_lines.append(f"cd {shlex.quote(cwd)}")
        script_lines.append(script_body)
        escaped_script = "\n".join(script_lines)
        ssh_cmd = f"ssh {shlex.quote(ssh_alias)} 'bash -s'"

    heredoc = f"cat << '__MAESTRO_SCRIPT__'\n{escaped_script}\n__MAESTRO_SCRIPT__"
    full_cmd = f"{heredoc} | {ssh_cmd}"

    lines = ["#!/bin/bash"]
    if tee:
        lines.append(f"{full_cmd} 2>&1 | tee {shlex.quote(str(output_file))}")
        lines.append(f"echo ${{PIPESTATUS[0]}} > {shlex.quote(str(rc_file))}")
    else:
        lines.append(full_cmd)
        lines.append(f"echo $? > {shlex.quote(str(rc_file))}")
    lines.append(f"tmux -L {TMUX_SERVER} wait-for -S 'done-{task_id}'")
    return "\n".join(lines)


# -----------------------------------------------------------------------
# Core primitives
# -----------------------------------------------------------------------

async def create_task_window(
    task_id: str,
    ssh_alias: str,
    command: str,
    *,
    tee: bool = True,
    interactive: bool = False,
    is_script: bool = False,
    cwd: str | None = None,
    sudo: bool = False,
    shell: str = "bash",
) -> Path | None:
    """Create a Hub-local tmux window that SSHes to the target host.

    Returns the output file path (if tee=True), or None for interactive.
    """
    await ensure_server()

    if is_script:
        wrapper = _build_script_wrapper(
            task_id, ssh_alias, command,
            tee=tee, cwd=cwd, sudo=sudo, shell=shell,
        )
    else:
        wrapper = _build_wrapper(
            task_id, ssh_alias, command,
            tee=(tee and not interactive), cwd=cwd, sudo=sudo, shell=shell,
        )

    # Write wrapper to temp file and run it in a new tmux window
    wrapper_path = OUTPUT_DIR / f"{task_id}.sh"
    wrapper_path.write_text(wrapper, encoding="utf-8")
    wrapper_path.chmod(0o755)

    window_name = f"task-{task_id[:12]}"
    await _tmux(
        "new-window",
        "-t", TMUX_SESSION,
        "-n", window_name,
        f"bash {shlex.quote(str(wrapper_path))}",
    )

    output_file = OUTPUT_DIR / f"{task_id}.txt" if (tee and not interactive) else None
    logger.info("mux: window '%s' → %s (task %s)", window_name, ssh_alias, task_id)
    return output_file


async def wait_for_completion(task_id: str, timeout: int = 300) -> int:
    """Block until a task signals completion. Zero-CPU wait. Returns exit code (-1 on timeout)."""
    proc = await asyncio.create_subprocess_exec(
        "tmux", "-L", TMUX_SERVER, "wait-for", f"done-{task_id}",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("mux: task %s hit ceiling after %ds", task_id, timeout)
        return -1

    rc_file = OUTPUT_DIR / f"{task_id}.rc"
    try:
        return int(rc_file.read_text().strip())
    except (FileNotFoundError, ValueError):
        logger.warning("mux: no rc file for task %s", task_id)
        return -1


async def capture_pane(task_id: str, lines: int = 50) -> str:
    """Capture live output from a task's tmux pane. Local read, zero SSH cost."""
    window_name = f"task-{task_id[:12]}"
    return await _tmux(
        "capture-pane", "-t", f"{TMUX_SESSION}:{window_name}",
        "-p", "-S", f"-{lines}",
    )


async def send_keys(task_id: str, keys: str) -> None:
    """Send keystrokes to a task's pane. Relayed through SSH to the remote process."""
    window_name = f"task-{task_id[:12]}"
    await _tmux(
        "send-keys", "-t", f"{TMUX_SESSION}:{window_name}",
        "--", keys,
    )


async def kill_window(task_id: str) -> None:
    """Kill a task's tmux window. SSH session dies → remote process terminates."""
    window_name = f"task-{task_id[:12]}"
    # Signal done so any wait_for_completion unblocks
    try:
        await _tmux("wait-for", "-S", f"done-{task_id}")
    except RuntimeError:
        pass  # window may already be gone
    try:
        await _tmux("kill-window", "-t", f"{TMUX_SESSION}:{window_name}")
    except RuntimeError:
        pass
    logger.info("mux: killed window '%s' (task %s)", window_name, task_id)


async def list_windows() -> list[dict[str, str]]:
    """List all task windows in the maestro tmux server."""
    raw = await _tmux(
        "list-windows", "-t", TMUX_SESSION,
        "-F", "#{window_name}|#{pane_current_command}|#{window_activity}",
    )
    if not raw:
        return []
    windows: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line or "|" not in line:
            continue
        parts = (line.split("|", 2) + ["", ""])[:3]
        windows.append({"name": parts[0], "command": parts[1], "activity": parts[2]})
    return windows


def get_output_path(task_id: str) -> Path:
    """Get the expected output file path for a task."""
    return OUTPUT_DIR / f"{task_id}.txt"


def get_rc_path(task_id: str) -> Path:
    """Get the expected exit code file path for a task."""
    return OUTPUT_DIR / f"{task_id}.rc"


def cleanup_task_files(task_id: str) -> None:
    """Remove wrapper and rc files for a completed task. Output file is retained."""
    for suffix in (".sh", ".rc"):
        (OUTPUT_DIR / f"{task_id}{suffix}").unlink(missing_ok=True)

