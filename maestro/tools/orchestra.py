"""Orchestra — task registry, auto-promote, and CLI runner helpers."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import shlex
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from maestro.config import MaestroConfig

logger = logging.getLogger("maestro")

AGENT_SCOPE_PREFIX = (
    "SCOPE CONSTRAINTS (non-negotiable):\n"
    "1. ONLY modify files and code directly related to the task below.\n"
    "2. Do NOT refactor, clean up, or improve code outside the task scope.\n"
    "3. Do NOT run tests unless explicitly asked.\n"
    "4. Do NOT update existing documentation unless explicitly asked.\n"
    "5. When done, write a brief debrief to docs/journal/debriefs/YYYY-MM-DD-{task-slug}.md "
    "with: task summary, files changed (1 sentence each), any surprises or decisions made.\n"
    "6. If the task is ambiguous, do the MINIMUM viable interpretation.\n\n"
    "TASK:\n"
)


# ---------------------------------------------------------------------------
# Task state + registry
# ---------------------------------------------------------------------------

@dataclass
class TaskState:
    task_id: str
    agent: str            # "codex" | "gemini" | "claude" | "exec" | "script"
    host: str
    prompt: str
    status: str           # "running" | "done" | "failed" | "timeout"
    started_at: datetime
    finished_at: datetime | None = None
    asyncio_task: asyncio.Task | None = None
    output_file: Path | None = None
    result_json: str | None = None
    last_polled_at: float = 0.0
    _done_event: asyncio.Event = field(default_factory=asyncio.Event)


TASK_REGISTRY: dict[str, TaskState] = {}
_REGISTRY_LOCK = asyncio.Lock()
_EVICTION_TASK: asyncio.Task | None = None

_REGISTRY_VERSION = 1


class TaskRegistryStore:
    """Atomic JSON persistence for the task registry."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        """Atomically serialize current registry to disk."""
        state: dict[str, Any] = {
            "version": _REGISTRY_VERSION,
            "saved_at": time.time(),
            "tasks": {},
        }
        for tid, ts in TASK_REGISTRY.items():
            state["tasks"][tid] = {
                "task_id": ts.task_id,
                "agent": ts.agent,
                "host": ts.host,
                "prompt": ts.prompt,
                "status": ts.status,
                "started_at": ts.started_at.isoformat(),
                "finished_at": ts.finished_at.isoformat() if ts.finished_at else None,
                "output_file": str(ts.output_file) if ts.output_file else None,
                "result_json": ts.result_json,
            }
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(state, indent=2))
            os.replace(tmp, self.path)
        except Exception as exc:
            logger.warning("task_registry: save failed: %s", exc)
            tmp.unlink(missing_ok=True)

    def load(self) -> None:
        """Load persisted tasks, marking any 'running' as 'orphaned'."""
        if not self.path.exists():
            logger.info("task_registry: no state file at %s — starting fresh", self.path)
            return
        try:
            state = json.loads(self.path.read_text())
        except Exception as exc:
            logger.warning("task_registry: failed to parse %s: %s — starting fresh", self.path, exc)
            return
        if state.get("version") != _REGISTRY_VERSION:
            logger.warning("task_registry: unsupported version — starting fresh")
            return

        loaded = orphaned = 0
        for tid, data in state.get("tasks", {}).items():
            try:
                status = data["status"]
                if status == "running":
                    status = "orphaned"
                    orphaned += 1
                ts = TaskState(
                    task_id=tid,
                    agent=data["agent"],
                    host=data["host"],
                    prompt=data["prompt"],
                    status=status,
                    started_at=datetime.fromisoformat(data["started_at"]),
                    finished_at=(
                        datetime.fromisoformat(data["finished_at"])
                        if data.get("finished_at")
                        else datetime.now(timezone.utc)
                    ),
                    output_file=Path(data["output_file"]) if data.get("output_file") else None,
                    result_json=data.get("result_json"),
                )
                ts._done_event.set()
                TASK_REGISTRY[tid] = ts
                loaded += 1
            except Exception as exc:
                logger.warning("task_registry: skip task %r: %s", tid, exc)
        logger.info("task_registry: loaded %d tasks (%d orphaned)", loaded, orphaned)


_TASK_STORE: TaskRegistryStore | None = None


def _save_registry() -> None:
    """Persist registry to disk if a store is configured."""
    if _TASK_STORE is not None:
        _TASK_STORE.save()


# ---------------------------------------------------------------------------
# Late-bound references (set by configure_orchestra)
# ---------------------------------------------------------------------------

_CONFIG: MaestroConfig | None = None
_RESOLVE_HOST: Callable[[str], Any] | None = None
_WRAP_COMMAND: Callable[..., str] | None = None
_FORMAT_RESULT: Callable[[str, str, int], str] | None = None
_UPDATE_HOST_STATUS: Callable[..., Awaitable[None]] | None = None
_HOST_STATUS: Any = None
_ENSURE_CONNECTION: Callable[..., Awaitable[bool]] | None = None
_TEARDOWN_CONNECTION: Callable[..., Awaitable[None]] | None = None
_ASYNC_RUN: Callable[..., Awaitable[tuple[int, str, str]]] | None = None
_IS_TRANSIENT_FAILURE: Callable[[int, str], bool] | None = None


def configure_orchestra(
    *,
    config: MaestroConfig,
    resolve_host: Callable[[str], Any],
    wrap_command: Callable[..., str],
    format_result: Callable[[str, str, int], str],
    update_host_status: Callable[..., Awaitable[None]],
    host_status: Any,
    ensure_connection: Callable[..., Awaitable[bool]],
    teardown_connection: Callable[..., Awaitable[None]],
    async_run: Callable[..., Awaitable[tuple[int, str, str]]],
    is_transient_failure: Callable[[int, str], bool],
    task_store: TaskRegistryStore | None = None,
) -> None:
    global _CONFIG, _RESOLVE_HOST, _WRAP_COMMAND, _FORMAT_RESULT
    global _UPDATE_HOST_STATUS, _HOST_STATUS, _ENSURE_CONNECTION
    global _TEARDOWN_CONNECTION, _ASYNC_RUN, _IS_TRANSIENT_FAILURE, _TASK_STORE
    _CONFIG = config
    _RESOLVE_HOST = resolve_host
    _WRAP_COMMAND = wrap_command
    _FORMAT_RESULT = format_result
    _UPDATE_HOST_STATUS = update_host_status
    _HOST_STATUS = host_status
    _ENSURE_CONNECTION = ensure_connection
    _TEARDOWN_CONNECTION = teardown_connection
    _ASYNC_RUN = async_run
    _IS_TRANSIENT_FAILURE = is_transient_failure
    _TASK_STORE = task_store


def _cfg() -> MaestroConfig:
    if _CONFIG is None:
        raise RuntimeError("orchestra not configured")
    return _CONFIG


# ---------------------------------------------------------------------------
# Eviction
# ---------------------------------------------------------------------------

async def _evict_stale_tasks() -> None:
    """Remove completed tasks older than task_eviction_seconds from registry."""
    cfg = _cfg()
    now = datetime.now(timezone.utc)
    async with _REGISTRY_LOCK:
        stale = [
            tid for tid, ts in TASK_REGISTRY.items()
            if ts.finished_at and (now - ts.finished_at).total_seconds() > cfg.task_eviction_seconds
        ]
        for tid in stale:
            ts = TASK_REGISTRY.pop(tid)
            if ts.asyncio_task and not ts.asyncio_task.done():
                ts.asyncio_task.cancel()
            if ts.output_file and ts.output_file.exists():
                try:
                    age = (now - ts.started_at).total_seconds()
                    if age > cfg.task_output_retention_seconds:
                        ts.output_file.unlink()
                except OSError:
                    pass
    if stale:
        logger.info(f"Orchestra: evicted {len(stale)} stale tasks from registry")
        _save_registry()


async def _periodic_eviction() -> None:
    """Background loop that evicts stale tasks every 10 minutes."""
    while True:
        await asyncio.sleep(600)
        try:
            await _evict_stale_tasks()
        except Exception:
            logger.exception("Orchestra: periodic eviction failed")


def start_eviction_loop() -> asyncio.Task:
    global _EVICTION_TASK
    _EVICTION_TASK = asyncio.create_task(_periodic_eviction())
    return _EVICTION_TASK


def cancel_eviction_loop() -> None:
    global _EVICTION_TASK
    if _EVICTION_TASK:
        _EVICTION_TASK.cancel()
        _EVICTION_TASK = None


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _orchestra_output_dir() -> Path:
    """Ensure orchestra output directory exists."""
    cfg = _cfg()
    cfg.orchestra_output_dir.mkdir(parents=True, exist_ok=True)
    return cfg.orchestra_output_dir


def _orchestra_output_path(agent: str, task_id: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _orchestra_output_dir() / f"{agent}_{ts}_{task_id}.txt"


def _orchestra_truncate(text: str, max_len: int | None = None) -> tuple[str, bool]:
    if max_len is None:
        max_len = _cfg().max_inline_output
    if len(text) <= max_len:
        return text, False
    return text[:max_len] + "\n... [truncated]", True


def _extract_gemini_response(raw_output: str) -> str:
    """Extract response text from Gemini CLI JSON envelope."""
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
    """Build structured result. Full output on disk, summary returned inline."""
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


# ---------------------------------------------------------------------------
# CLI runners
# ---------------------------------------------------------------------------

async def _orchestra_run_cli_raw(
    host: str,
    cli_command: str,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int, str, str]:
    """Run a CLI command and return structured (rc, stdout, stderr)."""
    assert _RESOLVE_HOST and _WRAP_COMMAND and _ASYNC_RUN
    assert _ENSURE_CONNECTION and _TEARDOWN_CONNECTION
    assert _UPDATE_HOST_STATUS and _HOST_STATUS and _IS_TRANSIENT_FAILURE
    cfg = _cfg()
    config = _RESOLVE_HOST(host)

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
        full_cmd = _WRAP_COMMAND(config, cli_command, cwd, False)
        last_stderr = ""
        for attempt in range(1, cfg.max_retries + 1):
            await _ENSURE_CONNECTION(config.alias, host)
            rc, stdout, stderr = await _ASYNC_RUN(
                ["ssh", config.alias, full_cmd], timeout=timeout,
            )
            if not _IS_TRANSIENT_FAILURE(rc, stderr):
                if rc not in (-1, 255):
                    await _UPDATE_HOST_STATUS(host, _HOST_STATUS.CONNECTED)
                elif stderr:
                    await _UPDATE_HOST_STATUS(host, _HOST_STATUS.ERROR, last_error=stderr.strip())
                return rc, stdout, stderr
            last_stderr = stderr.strip()
            if attempt < cfg.max_retries:
                backoff = cfg.retry_backoff_base * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)
                await _TEARDOWN_CONNECTION(config.alias)
        await _UPDATE_HOST_STATUS(host, _HOST_STATUS.ERROR, last_error=last_stderr)
        return -1, "", f"failed after {cfg.max_retries} attempts: {last_stderr}"


async def _orchestra_run_cli(
    host: str,
    cli_command: str,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int, str]:
    """Run a CLI command, returning (rc, formatted_output)."""
    assert _FORMAT_RESULT
    rc, stdout, stderr = await _orchestra_run_cli_raw(host, cli_command, timeout, cwd)
    combined = _FORMAT_RESULT(stdout, stderr, rc)
    return rc, combined


# ---------------------------------------------------------------------------
# Auto-promote: adaptive inline -> background execution
# ---------------------------------------------------------------------------

async def _auto_promote(
    execute_fn: Callable[[], Awaitable[str]],
    *,
    block_timeout: int,
    agent: str,
    host: str,
    prompt: str,
    output_file_factory: Callable[[str], Path] | None = None,
    output_holder: list[Path | None] | None = None,
) -> str:
    """Run execute_fn with adaptive blocking.

    Semantics of block_timeout:
      > 0  -- wait this many seconds inline, then auto-promote
      == 0 -- dispatch immediately (never block)
      < 0  -- block forever (legacy behaviour, no promotion)
    """
    task_id = secrets.token_hex(8)
    started_at = datetime.now(timezone.utc)
    output_file = output_file_factory(task_id) if output_file_factory else None
    if output_holder is not None:
        output_holder[0] = output_file

    work_task = asyncio.create_task(execute_fn())

    if block_timeout < 0:
        return await work_task

    if block_timeout > 0:
        try:
            result = await asyncio.wait_for(
                asyncio.shield(work_task),
                timeout=block_timeout,
            )
            return result
        except asyncio.TimeoutError:
            pass

    # Auto-promote: register as background task
    ts = TaskState(
        task_id=task_id,
        agent=agent,
        host=host,
        prompt=prompt[:200],
        status="running",
        started_at=started_at,
        asyncio_task=work_task,
        output_file=output_file,
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
            _save_registry()

    asyncio.create_task(_monitor())

    async with _REGISTRY_LOCK:
        TASK_REGISTRY[task_id] = ts
    _save_registry()

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
