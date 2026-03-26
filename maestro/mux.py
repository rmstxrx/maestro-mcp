from __future__ import annotations

import secrets
import shlex
from collections.abc import Awaitable, Callable
from typing import Any

from maestro.config import MaestroConfig
from maestro.hosts import HostShell

TMUX_SERVER = "maestro"
TMUX_SESSION = "main"
TEMP_PREFIX = "/tmp/maestro_run_"

_ResolveHost = Callable[[str], Any]
_Run = Callable[..., Awaitable[str]]

_CONFIG: MaestroConfig | None = None
_RESOLVE_HOST: _ResolveHost | None = None
_SSH_RUN: _Run | None = None
_LOCAL_RUN: _Run | None = None
_FORMAT_RESULT: Callable[[str, str, int], str] | None = None


def configure_mux(
    *,
    config: MaestroConfig,
    resolve_host: _ResolveHost,
    ssh_run: _Run,
    local_run: _Run,
    format_result: Callable[[str, str, int], str],
) -> None:
    global _CONFIG, _RESOLVE_HOST, _SSH_RUN, _LOCAL_RUN, _FORMAT_RESULT
    _CONFIG = config
    _RESOLVE_HOST = resolve_host
    _SSH_RUN = ssh_run
    _LOCAL_RUN = local_run
    _FORMAT_RESULT = format_result


def _require_config() -> MaestroConfig:
    if _CONFIG is None:
        raise RuntimeError("mux helpers are not configured")
    return _CONFIG


def _resolve_host_config(host: str) -> Any:
    if _RESOLVE_HOST is None:
        raise RuntimeError("mux helpers are not configured")
    return _RESOLVE_HOST(host)


def _format_result(stdout: str, stderr: str, returncode: int) -> str:
    if _FORMAT_RESULT is None:
        raise RuntimeError("mux helpers are not configured")
    return _FORMAT_RESULT(stdout, stderr, returncode)


async def _ssh_run(
    host: str,
    ssh_args: list[str],
    *,
    timeout: int,
    stdin_data: str | None = None,
) -> str:
    if _SSH_RUN is None:
        raise RuntimeError("mux helpers are not configured")
    return await _SSH_RUN(host, ssh_args, timeout=timeout, stdin_data=stdin_data)


async def _local_run(
    command: str,
    *,
    timeout: int,
    stdin_data: str | None = None,
) -> str:
    if _LOCAL_RUN is None:
        raise RuntimeError("mux helpers are not configured")
    return await _LOCAL_RUN(command, timeout=timeout, stdin_data=stdin_data)


def _session_bootstrap_command() -> str:
    return (
        f"tmux -L {TMUX_SERVER} has-session -t {TMUX_SESSION} 2>/dev/null || "
        f"tmux -L {TMUX_SERVER} new-session -d -s {TMUX_SESSION}"
    )


def _build_ephemeral_wrapper(
    command: str,
    run_id: str,
    cwd: str | None = None,
    sudo: bool = False,
) -> str:
    """Build the bash wrapper script for tmux ephemeral execution."""
    runner = "sudo bash" if sudo else "bash"
    tmux_parts = [f"tmux -L {TMUX_SERVER} new-window"]
    if cwd:
        tmux_parts.append(f"-c {shlex.quote(cwd)}")
    tmux_parts.append(f"-t {TMUX_SESSION}")
    tmux_parts.append(
        f'"{runner} \\"$_MUX_CMD\\" > \\"$_MUX_OUT\\" 2>&1; '
        'echo \\$? > \\"$_MUX_RC\\"; rm -f \\"$_MUX_CMD\\""'
    )
    window_command = " ".join(tmux_parts)

    lines = [
        "set -e",
        _session_bootstrap_command(),
        "",
        f'_MUX_ID="{run_id}"',
        f'_MUX_CMD="{TEMP_PREFIX}${{_MUX_ID}}.cmd"',
        f'_MUX_OUT="{TEMP_PREFIX}${{_MUX_ID}}.out"',
        f'_MUX_RC="{TEMP_PREFIX}${{_MUX_ID}}.rc"',
        "",
        'cat > "$_MUX_CMD" << \'__MAESTRO_CMD_END__\'',
        command,
        "__MAESTRO_CMD_END__",
        "",
        window_command,
        "",
        'while [ ! -f "$_MUX_RC" ]; do sleep 0.01; done',
        "",
        'cat "$_MUX_OUT"',
        '_MUX_EXIT=$(cat "$_MUX_RC")',
        "",
        'rm -f "$_MUX_OUT" "$_MUX_RC"',
        "",
        "exit $_MUX_EXIT",
    ]
    return "\n".join(lines)


async def ensure_session(host: str) -> bool:
    """Verify the maestro tmux server is alive on the given host. Creates it if absent."""
    cfg = _resolve_host_config(host)
    if cfg.shell == HostShell.POWERSHELL:
        return False

    marker = "__MAESTRO_MUX_READY__"
    expected = _format_result(marker, "", 0)
    command = f"{_session_bootstrap_command()} && printf %s {shlex.quote(marker)}"
    timeout = _require_config().ssh_timeout

    if cfg.is_local:
        result = await _local_run(command, timeout=timeout)
    else:
        result = await _ssh_run(host, ["bash", "-lc", command], timeout=timeout)

    return result == expected


async def mux_run(
    host: str,
    command: str,
    timeout: int = 300,
    cwd: str | None = None,
    sudo: bool = False,
) -> str:
    """Execute a command in a tmux ephemeral window on the given host."""
    cfg = _resolve_host_config(host)
    if cfg.shell == HostShell.POWERSHELL:
        raise ValueError("mux_run does not support PowerShell hosts")

    wrapper_script = _build_ephemeral_wrapper(command, secrets.token_hex(4), cwd=cwd, sudo=sudo)
    if cfg.is_local:
        return await _local_run("bash -s", timeout=timeout, stdin_data=wrapper_script)
    return await _ssh_run(host, ["bash", "-s"], timeout=timeout, stdin_data=wrapper_script)
