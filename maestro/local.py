from __future__ import annotations

import asyncio
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from maestro.config import MaestroConfig

_CONFIG: MaestroConfig | None = None
_FORMAT_RESULT: Callable[[str, str, int], str] | None = None


def configure_local(config: MaestroConfig, format_result: Callable[[str, str, int], str]) -> None:
    global _CONFIG, _FORMAT_RESULT
    _CONFIG = config
    _FORMAT_RESULT = format_result


def _format_result(stdout: str, stderr: str, returncode: int) -> str:
    if _FORMAT_RESULT is None:
        raise RuntimeError("local helpers are not configured")
    return _FORMAT_RESULT(stdout, stderr, returncode)


async def _local_run(
    command: str,
    timeout: int | None = None,
    stdin_data: str | None = None,
    cwd: str | None = None,
) -> str:
    if _CONFIG is None:
        raise RuntimeError("local helpers are not configured")
    used_timeout = timeout if timeout is not None else _CONFIG.ssh_timeout
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash",
            "-c",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
            cwd=cwd,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=used_timeout,
        )
        rc = proc.returncode or 0
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        return _format_result(stdout, stderr, rc)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"[local timeout after {used_timeout}s]"
    except FileNotFoundError as e:
        return f"[local error] binary not found: {e}"


async def _local_script(
    script: str,
    timeout: int | None = None,
    cwd: str | None = None,
    sudo: bool = False,
) -> str:
    if _CONFIG is None:
        raise RuntimeError("local helpers are not configured")
    used_timeout = timeout if timeout is not None else _CONFIG.ssh_timeout
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
            timeout=used_timeout,
        )
        rc = proc.returncode or 0
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        return _format_result(stdout, stderr, rc)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"[local timeout after {used_timeout}s]"


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
