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

from maestro.hosts import HostShell

logger = logging.getLogger("maestro")

TMUX_SERVER = "maestro"
TMUX_SESSION = "tasks"
OUTPUT_DIR = Path("/root/.maestro/task_output")
HOST_OUTPUT_RETENTION_DAYS = 30
STAGING_INBOX = Path("/tmp/maestro/inbox")
STAGING_OUTBOX = Path("/tmp/maestro/outbox")


def _staging_mkdir_cmd(shell: HostShell) -> str:
    if shell == HostShell.POWERSHELL:
        return (
            "New-Item -ItemType Directory -Force -ErrorAction SilentlyContinue -Path '/tmp/maestro/inbox'; "
            "New-Item -ItemType Directory -Force -ErrorAction SilentlyContinue -Path '/tmp/maestro/outbox'"
        )
    return "mkdir -p /tmp/maestro/inbox /tmp/maestro/outbox"


def _staging_cleanup_cmd(shell: HostShell) -> str:
    if shell == HostShell.POWERSHELL:
        return (
            "Get-ChildItem '/tmp/maestro' -Recurse -File | "
            "Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-60) } | "
            "Remove-Item -Force -ErrorAction SilentlyContinue"
        )
    return "find /tmp/maestro -mmin +60 -delete 2>/dev/null || true"


def configure_mux(
    *,
    output_dir: Path | None = None,
    host_output_retention_days: int | None = None,
) -> None:
    """Set the output directory for task captures. Called once at startup."""
    global OUTPUT_DIR, HOST_OUTPUT_RETENTION_DAYS
    if output_dir is not None:
        OUTPUT_DIR = output_dir
    if host_output_retention_days is not None:
        HOST_OUTPUT_RETENTION_DAYS = host_output_retention_days
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


def _build_staged_wrapper(
    task_id: str,
    ssh_alias: str,
    *,
    tee: bool = True,
    cwd: str | None = None,
    sudo: bool = False,
    stream: bool = False,
    shell: HostShell = HostShell.BASH,
) -> str:
    """Build wrapper that executes a pre-staged script from /tmp/maestro/inbox."""
    output_file = OUTPUT_DIR / f"{task_id}.txt"
    rc_file = OUTPUT_DIR / f"{task_id}.rc"
    inbox_script = f"/tmp/maestro/inbox/{task_id}.sh"
    outbox_out = f"/tmp/maestro/outbox/{task_id}.out"
    outbox_rc = f"/tmp/maestro/outbox/{task_id}.rc"

    remote_parts = [
        _staging_mkdir_cmd(shell),
        _staging_cleanup_cmd(shell),
    ]
    if cwd:
        remote_parts.append(f"cd {shlex.quote(cwd)}")
    exec_cmd = f"sudo bash {inbox_script}" if sudo else f"bash {inbox_script}"
    if stream:
        remote_parts.append(exec_cmd)
    else:
        remote_parts.append(f"{{ {exec_cmd}; }} > {outbox_out} 2>&1; _RC=$?; echo $_RC > {outbox_rc}; exit $_RC")
    remote_cmd = " && ".join(remote_parts)

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


async def stage_script(
    task_id: str,
    ssh_alias: str,
    content: str,
    shell: HostShell = HostShell.BASH,
) -> None:
    """Write a script to the remote host's /tmp/maestro/inbox via SSH.

    Used by dispatch and service to pre-stage their commands before
    triggering execution via create_task_window.
    """
    inbox_path = f"/tmp/maestro/inbox/{task_id}.sh"
    if shell == HostShell.POWERSHELL:
        cmd = (
            "New-Item -ItemType Directory -Force -ErrorAction SilentlyContinue -Path '/tmp/maestro/inbox'; "
            "$script = [System.IO.StreamReader]::new([System.Console]::OpenStandardInput()).ReadToEnd(); "
            f"Set-Content -Path {shlex.quote(inbox_path)} -Value $script -Encoding UTF8 -Force"
        )
    else:
        cmd = f"mkdir -p /tmp/maestro/inbox && cat > {inbox_path} && chmod +x {inbox_path}"
    proc = await asyncio.create_subprocess_exec(
        "ssh", ssh_alias, cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=content.encode("utf-8")), timeout=30,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"stage_script timed out on {ssh_alias}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"stage_script failed on {ssh_alias}: "
            f"{stderr_bytes.decode(errors='replace').strip()}"
        )
    logger.debug("mux: staged script %s on %s (%d bytes)", inbox_path, ssh_alias, len(content))


# -----------------------------------------------------------------------
# Core primitives
# -----------------------------------------------------------------------

async def create_task_window(
    task_id: str,
    ssh_alias: str,
    *,
    tee: bool = True,
    interactive: bool = False,
    cwd: str | None = None,
    sudo: bool = False,
    stream: bool = False,
    shell: HostShell = HostShell.BASH,
) -> Path | None:
    """Create a Hub-local tmux window that SSHes to the target host.

    Returns the output file path (if tee=True), or None for interactive.
    """
    await ensure_server()

    wrapper = _build_staged_wrapper(
        task_id,
        ssh_alias,
        tee=tee,
        cwd=cwd,
        sudo=sudo,
        stream=stream,
        shell=shell,
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
