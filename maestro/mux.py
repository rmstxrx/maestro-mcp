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
import secrets
from pathlib import Path

logger = logging.getLogger("maestro")

TMUX_SERVER = "maestro"
TMUX_SESSION = "tasks"
OUTPUT_DIR = Path("/root/.maestro/task_output")
HOST_OUTPUT_RETENTION_DAYS = 30
STAGING_INBOX = Path("/tmp/maestro/inbox")
STAGING_OUTBOX = Path("/tmp/maestro/outbox")


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


def _remote_preamble(shell: str) -> str:
    """Build remote output-dir bootstrap and retention cleanup commands."""
    if shell == "powershell":
        return (
            "if (!(Test-Path ~/.maestro/task_output)) { "
            "New-Item -ItemType Directory -Path ~/.maestro/task_output -Force | Out-Null }; "
            f"if (!(Test-Path {STAGING_INBOX})) {{ "
            "New-Item -ItemType Directory -Path /tmp/maestro/inbox -Force | Out-Null }; "
            f"if (!(Test-Path {STAGING_OUTBOX})) {{ "
            "New-Item -ItemType Directory -Path /tmp/maestro/outbox -Force | Out-Null }; "
            "Get-ChildItem /tmp/maestro -Recurse -File -ErrorAction SilentlyContinue | "
            "Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-60) } | "
            "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; "
            "Get-ChildItem ~/.maestro/task_output -Filter '*.txt' | "
            "Where-Object { $_.LastWriteTime -lt "
            f"(Get-Date).AddDays(-{HOST_OUTPUT_RETENTION_DAYS}) }} | "
            "Remove-Item -Force -ErrorAction SilentlyContinue;"
        )
    return (
        "mkdir -p ~/.maestro/task_output && "
        "mkdir -p /tmp/maestro/inbox /tmp/maestro/outbox && "
        "find /tmp/maestro -mmin +60 -delete 2>/dev/null && "
        f"find ~/.maestro/task_output -name '*.txt' -mtime +{HOST_OUTPUT_RETENTION_DAYS} "
        "-delete 2>/dev/null;"
    )


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
    remote_output_file = f"~/.maestro/task_output/{task_id}.txt"
    remote_preamble = _remote_preamble(shell)

    # Build the remote command
    if shell == "powershell":
        remote_parts = []
        if cwd:
            remote_parts.append(f"Set-Location -LiteralPath '{cwd}';")
        remote_parts.append(f"sudo {command}" if sudo else command)
        remote_core_cmd = " ".join(remote_parts)
        if tee:
            remote_cmd = (
                f"{remote_preamble} & {{ {remote_core_cmd} }} 2>&1 | "
                f"Tee-Object -FilePath {remote_output_file}"
            )
        else:
            remote_cmd = remote_core_cmd
    else:
        remote_parts = []
        if cwd:
            remote_parts.append(f"cd {shlex.quote(cwd)} &&")
        if sudo:
            remote_parts.append("sudo")
        remote_parts.append(command)
        remote_core_cmd = " ".join(remote_parts)
        if tee:
            remote_cmd = f"{remote_preamble} {{ {remote_core_cmd}; }} 2>&1 | tee {remote_output_file}"
        else:
            remote_cmd = remote_core_cmd

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


def _build_staged_wrapper(
    task_id: str,
    ssh_alias: str,
    *,
    tee: bool = True,
    cwd: str | None = None,
    sudo: bool = False,
) -> str:
    """Build wrapper that executes a pre-staged script from /tmp/maestro/inbox."""
    output_file = OUTPUT_DIR / f"{task_id}.txt"
    rc_file = OUTPUT_DIR / f"{task_id}.rc"
    inbox_script = f"/tmp/maestro/inbox/{task_id}.sh"
    outbox_out = f"/tmp/maestro/outbox/{task_id}.out"
    outbox_rc = f"/tmp/maestro/outbox/{task_id}.rc"

    remote_parts = [
        "mkdir -p /tmp/maestro/inbox /tmp/maestro/outbox",
        "find /tmp/maestro -mmin +60 -delete 2>/dev/null",
    ]
    if cwd:
        remote_parts.append(f"cd {shlex.quote(cwd)}")
    exec_cmd = f"sudo bash {inbox_script}" if sudo else f"bash {inbox_script}"
    remote_parts.append(f"{{ {exec_cmd}; }} > {outbox_out} 2>&1; echo $? > {outbox_rc}")
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


# -----------------------------------------------------------------------
# Core primitives
# -----------------------------------------------------------------------

async def create_task_window(
    task_id: str,
    ssh_alias: str,
    command: str | None = None,
    *,
    tee: bool = True,
    interactive: bool = False,
    cwd: str | None = None,
    sudo: bool = False,
    shell: str = "bash",
    staged: bool = False,
) -> Path | None:
    """Create a Hub-local tmux window that SSHes to the target host.

    Returns the output file path (if tee=True), or None for interactive.
    """
    await ensure_server()

    if staged:
        # Deprecated command wrappers are retained for dispatch compatibility in ADR-0007/4.
        wrapper = _build_staged_wrapper(
            task_id,
            ssh_alias,
            tee=tee,
            cwd=cwd,
            sudo=sudo,
        )
    else:
        if command is None:
            raise ValueError("command is required unless staged=True")
        # Deprecated command-based wrapper kept for compatibility until ADR-0009 phase 4.
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


async def mux_spawn(
    host: str,
    command: str,
    name: str,
    timeout: int,
    *,
    cwd: str | None = None,
    sudo: bool = False,
    cleanup: bool = False,
) -> str:
    """Compatibility wrapper for callers expecting named-window command execution."""
    task_id = secrets.token_hex(8)
    await create_task_window(
        task_id,
        host,
        command,
        tee=True,
        interactive=False,
        cwd=cwd,
        sudo=sudo,
        shell="bash",
    )
    rc = await wait_for_completion(task_id, timeout=timeout)

    output = ""
    output_file = get_output_path(task_id)
    if output_file.exists():
        output = output_file.read_text(encoding="utf-8", errors="replace").rstrip("\n")
    if output:
        output = f"{output}\n[exit code: {rc}]"
    else:
        output = f"[exit code: {rc}]"

    if cleanup:
        cleanup_task_files(task_id)
    return output


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
