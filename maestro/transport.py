from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from maestro.config import MaestroConfig

logger = logging.getLogger("maestro")

TRANSIENT_INDICATORS = [
    "Connection refused",
    "Connection timed out",
    "Connection reset",
    "Broken pipe",
    "Control socket connect",
    "No route to host",
    "Network is unreachable",
    "ssh_exchange_identification",
    "Connection closed by remote host",
    "mux_client_request_session: session request failed",
]

_ResolveHost = Callable[[str], Any]
_UpdateHostStatus = Callable[[str, Any, str], Awaitable[None]]

_CONFIG: MaestroConfig | None = None
_HOSTS: dict[str, Any] = {}
_HOST_LOCKS: dict[str, asyncio.Lock] = {}
_RESOLVE_HOST: _ResolveHost | None = None
_UPDATE_HOST_STATUS: _UpdateHostStatus | None = None
_HOST_STATUS = None
_FORMAT_RESULT: Callable[[str, str, int], str] | None = None


def configure_transport(
    config: MaestroConfig,
    hosts: dict[str, Any],
    locks: dict[str, asyncio.Lock],
    update_host_status: _UpdateHostStatus,
    resolve_host: _ResolveHost,
    host_status: Any,
    format_result: Callable[[str, str, int], str],
) -> None:
    global _CONFIG, _HOSTS, _HOST_LOCKS, _RESOLVE_HOST, _UPDATE_HOST_STATUS, _HOST_STATUS, _FORMAT_RESULT
    _CONFIG = config
    _HOSTS = hosts
    _HOST_LOCKS = locks
    _RESOLVE_HOST = resolve_host
    _UPDATE_HOST_STATUS = update_host_status
    _HOST_STATUS = host_status
    _FORMAT_RESULT = format_result


def _require_config() -> MaestroConfig:
    if _CONFIG is None:
        raise RuntimeError("transport helpers are not configured")
    return _CONFIG


def _resolve_host(host: str) -> Any:
    if _RESOLVE_HOST is None:
        raise RuntimeError("transport helpers are not configured")
    return _RESOLVE_HOST(host)


def _update_status(name: str, status: Any, last_error: str = "") -> Awaitable[None]:
    if _UPDATE_HOST_STATUS is None:
        raise RuntimeError("transport helpers are not configured")
    return _UPDATE_HOST_STATUS(name, status, last_error)


def _format_result(stdout: str, stderr: str, returncode: int) -> str:
    if _FORMAT_RESULT is None:
        raise RuntimeError("transport helpers are not configured")
    return _FORMAT_RESULT(stdout, stderr, returncode)


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


async def _check_control_master(alias: str) -> bool:
    rc, _, _ = await _async_run(["ssh", "-O", "check", alias], timeout=5)
    return rc == 0


async def _warmup_connection(alias: str) -> bool:
    rc, _, _ = await _async_run(["ssh", alias, "true"], timeout=15)
    return rc == 0


async def _teardown_connection(alias: str) -> None:
    await _async_run(["ssh", "-O", "exit", alias], timeout=5)


async def warmup_all_hosts() -> dict[str, bool]:
    async def _warmup_one(name: str, config: Any) -> tuple[str, bool]:
        if config.is_local:
            await _update_status(name, _HOST_STATUS.CONNECTED)
            logger.info(f"{name}: local host (no SSH needed)")
            return name, True
        if await _check_control_master(config.alias):
            logger.info(f"{name}: ControlMaster already active")
            await _update_status(name, _HOST_STATUS.CONNECTED)
            return name, True
        logger.info(f"{name}: warming up connection...")
        success = await _warmup_connection(config.alias)
        status = _HOST_STATUS.CONNECTED if success else _HOST_STATUS.DISCONNECTED
        await _update_status(name, status)
        if success:
            logger.info(f"{name}: connected")
        else:
            logger.warning(f"{name}: warmup failed (host may be offline)")
        return name, success

    tasks = [_warmup_one(name, config) for name, config in _HOSTS.items()]
    pairs = await asyncio.gather(*tasks)
    return dict(pairs)


async def teardown_all_hosts() -> None:
    names: list[str] = []
    tasks = []
    for name, config in _HOSTS.items():
        if config.is_local:
            continue
        logger.info(f"{name}: tearing down ControlMaster")
        names.append(name)
        tasks.append(_teardown_connection(config.alias))
        config.status = _HOST_STATUS.DISCONNECTED
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                logger.warning(f"Teardown failed for {name}: {result}")


def _is_transient_failure(returncode: int, stderr: str) -> bool:
    if returncode not in (-1, 255):
        return False
    return any(ind in stderr for ind in TRANSIENT_INDICATORS)


async def _ensure_connection(alias: str, host_name: str) -> bool:
    """Ensure ControlMaster is alive, serialized per host to avoid reconnection races."""
    config = _resolve_host(host_name)
    async with _HOST_LOCKS[host_name]:
        if await _check_control_master(alias):
            return True
        logger.info(f"ControlMaster for {config.alias} is dead, re-warming...")
        return await _warmup_connection(alias)


async def _ssh_run(
    host_name: str,
    ssh_args: list[str],
    timeout: int = 300,
    stdin_data: str | None = None,
) -> str:
    config = _resolve_host(host_name)
    last_error = ""
    config_obj = _require_config()
    for attempt in range(1, config_obj.max_retries + 1):
        await _ensure_connection(config.alias, host_name)
        rc, stdout, stderr = await _async_run(
            ["ssh", config.alias, *ssh_args],
            timeout=timeout,
            stdin_data=stdin_data,
        )
        if rc not in (-1, 255):
            await _update_status(host_name, _HOST_STATUS.CONNECTED)
            return _format_result(stdout, stderr, rc)
        if not _is_transient_failure(rc, stderr):
            await _update_status(host_name, _HOST_STATUS.ERROR, last_error=stderr.strip())
            return f"[SSH error on {host_name}]\n{stderr}"
        last_error = stderr.strip() or f"rc={rc}"
        logger.warning(f"{host_name}: transient failure (attempt {attempt}/{config_obj.max_retries}): {last_error}")
        if attempt < config_obj.max_retries:
            backoff = config_obj.retry_backoff_base * (2 ** (attempt - 1))
            logger.info(f"Retrying in {backoff}s...")
            await asyncio.sleep(backoff)
            await _teardown_connection(config.alias)
    await _update_status(host_name, _HOST_STATUS.ERROR, last_error=last_error)
    return f"[failed after {config_obj.max_retries} attempts on {host_name}]\nLast error: {last_error}"


async def _scp_run(
    host_name: str,
    source: str,
    destination: str,
    upload: bool = True,
    timeout: int = 300,
) -> str:
    config = _resolve_host(host_name)
    if upload:
        scp_args = ["scp", source, f"{config.alias}:{destination}"]
        action_desc = f"upload {source} -> {host_name}:{destination}"
    else:
        scp_args = ["scp", f"{config.alias}:{source}", destination]
        action_desc = f"download {host_name}:{source} -> {destination}"
    last_error = ""
    config_obj = _require_config()
    for attempt in range(1, config_obj.max_retries + 1):
        await _ensure_connection(config.alias, host_name)
        rc, stdout, stderr = await _async_run(scp_args, timeout=timeout)
        if rc == 0:
            await _update_status(host_name, _HOST_STATUS.CONNECTED)
            return f"[OK] {action_desc}"
        if not _is_transient_failure(rc, stderr):
            return f"[scp failed on {host_name}]\n{stderr}"
        last_error = stderr.strip()
        logger.warning(f"{host_name}: scp transient failure (attempt {attempt}/{config_obj.max_retries}): {last_error}")
        if attempt < config_obj.max_retries:
            backoff = config_obj.retry_backoff_base * (2 ** (attempt - 1))
            await asyncio.sleep(backoff)
            await _teardown_connection(config.alias)
    await _update_status(host_name, _HOST_STATUS.ERROR, last_error=last_error)
    return f"[scp failed after {config_obj.max_retries} attempts on {host_name}]\n{last_error}"
