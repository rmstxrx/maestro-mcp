"""Orchestra — task registry, auto-promote, CLI helpers, and MCP tools."""

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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from maestro.client import get_client_context
from maestro.config import MaestroConfig
from maestro.transport import _structured_error

logger = logging.getLogger("maestro")

AGENT_SCOPE_PREFIX = (
    "MANDATORY: Read ~/Development/General/AGENTS.md before starting.\n"
    "It contains conduct rules and pointers to fleet documentation you must follow.\n\n"
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
_LEDGER_VERSION = 1


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


@dataclass
class TaskLedgerEntry:
    task_id: str
    agent: str
    host: str
    prompt: str
    status: str
    client_class: str
    dispatched_at: datetime
    completed_at: datetime | None = None
    return_code: int | None = None
    output_file: str | None = None
    result_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent": self.agent,
            "host": self.host,
            "prompt": self.prompt,
            "status": self.status,
            "client_class": self.client_class,
            "dispatched_at": self.dispatched_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "return_code": self.return_code,
            "output_file": self.output_file,
            "result_url": self.result_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskLedgerEntry":
        return cls(
            task_id=data["task_id"],
            agent=data["agent"],
            host=data["host"],
            prompt=data["prompt"],
            status=data["status"],
            client_class=data["client_class"],
            dispatched_at=datetime.fromisoformat(data["dispatched_at"]),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if data.get("completed_at")
                else None
            ),
            return_code=data.get("return_code"),
            output_file=data.get("output_file"),
            result_url=data.get("result_url", ""),
        )


class TaskLedger:
    """Persistent task metadata ledger."""

    def __init__(self, path: Path, issuer_url: str) -> None:
        self.path = path.expanduser()
        self.issuer_url = issuer_url.rstrip("/")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, TaskLedgerEntry] = {}
        self._load()

    def record(self, entry: TaskLedgerEntry) -> None:
        """Insert or replace a task ledger entry."""
        if not entry.result_url:
            entry.result_url = self._result_url(entry.task_id)
        self._entries[entry.task_id] = entry
        self._save()

    def update(self, task_id: str, **fields: Any) -> None:
        """Partially update an existing ledger entry."""
        entry = self._entries.get(task_id)
        if entry is None:
            logger.warning("task_ledger: task %r not found for update", task_id)
            return
        for key, value in fields.items():
            if not hasattr(entry, key):
                continue
            setattr(entry, key, value)
        if not entry.result_url:
            entry.result_url = self._result_url(task_id)
        self._save()

    def query(
        self,
        *,
        status: str | None = None,
        agent: str | None = None,
        host: str | None = None,
        last: int = 10,
    ) -> list[TaskLedgerEntry]:
        """Return recent ledger entries, filtered by exact-match fields."""
        entries = list(self._entries.values())
        if status is not None:
            entries = [entry for entry in entries if entry.status == status]
        if agent is not None:
            entries = [entry for entry in entries if entry.agent == agent]
        if host is not None:
            entries = [entry for entry in entries if entry.host == host]
        entries.sort(key=lambda entry: entry.dispatched_at, reverse=True)
        return entries[: max(last, 0)]

    def get(self, task_id: str) -> TaskLedgerEntry | None:
        """Look up a single task by task ID."""
        return self._entries.get(task_id)

    def _save(self) -> None:
        state = {
            "version": _LEDGER_VERSION,
            "saved_at": time.time(),
            "tasks": {
                task_id: entry.to_dict()
                for task_id, entry in self._entries.items()
            },
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception as exc:
            logger.warning("task_ledger: save failed: %s", exc)
            tmp.unlink(missing_ok=True)

    def _load(self) -> None:
        if not self.path.exists():
            logger.info("task_ledger: no state file at %s — starting fresh", self.path)
            return
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("task_ledger: failed to parse %s: %s — starting fresh", self.path, exc)
            return
        if state.get("version") != _LEDGER_VERSION:
            logger.warning("task_ledger: unsupported version — starting fresh")
            return

        loaded = orphaned = 0
        orphaned_at = datetime.now(timezone.utc)
        for task_id, data in state.get("tasks", {}).items():
            try:
                entry = TaskLedgerEntry.from_dict(data)
                if entry.status == "running":
                    entry.status = "orphaned"
                    entry.completed_at = entry.completed_at or orphaned_at
                    orphaned += 1
                if not entry.result_url:
                    entry.result_url = self._result_url(task_id)
                self._entries[task_id] = entry
                loaded += 1
            except Exception as exc:
                logger.warning("task_ledger: skip task %r: %s", task_id, exc)
        logger.info("task_ledger: loaded %d tasks (%d orphaned)", loaded, orphaned)

    def _prune(self, max_age_days: int = 30) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        stale = [
            task_id
            for task_id, entry in self._entries.items()
            if (entry.completed_at or entry.dispatched_at) < cutoff
        ]
        for task_id in stale:
            self._entries.pop(task_id, None)
        if stale:
            self._save()

    def _result_url(self, task_id: str) -> str:
        return f"{self.issuer_url}/tasks/{task_id}/result"


_TASK_STORE: TaskRegistryStore | None = None
_TASK_LEDGER: TaskLedger | None = None


def _save_registry() -> None:
    """Persist registry to disk if a store is configured."""
    if _TASK_STORE is not None:
        _TASK_STORE.save()


def get_task_ledger() -> TaskLedger | None:
    """Return the configured task ledger, if any."""
    return _TASK_LEDGER


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
    task_ledger: TaskLedger | None = None,
) -> None:
    global _CONFIG, _RESOLVE_HOST, _WRAP_COMMAND, _FORMAT_RESULT
    global _UPDATE_HOST_STATUS, _HOST_STATUS, _ENSURE_CONNECTION
    global _TEARDOWN_CONNECTION, _ASYNC_RUN, _IS_TRANSIENT_FAILURE
    global _TASK_STORE, _TASK_LEDGER
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
    _TASK_LEDGER = task_ledger


def _cfg() -> MaestroConfig:
    if _CONFIG is None:
        raise RuntimeError("orchestra not configured")
    return _CONFIG


def _resolve_host_config(host: str) -> Any:
    if _RESOLVE_HOST is None:
        raise RuntimeError("orchestra not configured")
    return _RESOLVE_HOST(host)


def _format_relative_time(ts: datetime, now: datetime | None = None) -> str:
    """Format a timestamp as a compact relative age string."""
    current = now or datetime.now(timezone.utc)
    seconds = max(int((current - ts).total_seconds()), 0)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


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


def _extract_return_code(result_json: str | None) -> int | None:
    """Best-effort extraction of a return code from a task result payload."""
    if not result_json:
        return None
    try:
        parsed = json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    value = parsed.get("return_code")
    if isinstance(value, int):
        return value
    output = parsed.get("output")
    if not isinstance(output, str):
        return None
    marker = "[exit code: "
    if marker not in output:
        return None
    suffix = output.rsplit(marker, 1)[-1]
    try:
        return int(suffix.split("]", 1)[0])
    except (TypeError, ValueError):
        return None


def _record_ledger_entry(
    *,
    task_id: str,
    agent: str,
    host: str,
    prompt: str,
    client_class: str,
    dispatched_at: datetime,
    output_file: Path | None,
) -> None:
    if _TASK_LEDGER is None:
        return
    _TASK_LEDGER.record(
        TaskLedgerEntry(
            task_id=task_id,
            agent=agent,
            host=host,
            prompt=prompt[:200],
            status="running",
            client_class=client_class,
            dispatched_at=dispatched_at,
            output_file=str(output_file) if output_file else None,
        )
    )


def _complete_ledger_entry(
    *,
    task_id: str,
    status: str,
    result_json: str | None,
    output_file: Path | None,
    completed_at: datetime,
) -> None:
    if _TASK_LEDGER is None:
        return
    _TASK_LEDGER.update(
        task_id,
        status=status,
        completed_at=completed_at,
        return_code=_extract_return_code(result_json),
        output_file=str(output_file) if output_file else None,
    )


# ---------------------------------------------------------------------------
# CLI runners
# ---------------------------------------------------------------------------

async def _orchestra_run_cli_raw_ps(
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
    window_name: str | None = None,
) -> tuple[int, str]:
    """Run a CLI command via mux, returning (rc, formatted_output)."""
    from maestro.hosts import HostShell
    from maestro.mux import mux_run, mux_spawn

    assert _FORMAT_RESULT
    cfg = _RESOLVE_HOST(host) if _RESOLVE_HOST else None
    if cfg and cfg.shell == HostShell.POWERSHELL:
        rc, stdout, stderr = await _orchestra_run_cli_raw_ps(host, cli_command, timeout, cwd)
        return rc, _FORMAT_RESULT(stdout, stderr, rc)

    if window_name:
        raw = await mux_spawn(host, cli_command, name=window_name, timeout=timeout, cwd=cwd)
    else:
        raw = await mux_run(host, cli_command, timeout=timeout, cwd=cwd)

    rc = 0
    marker = "[exit code: "
    if marker in raw:
        try:
            rc = int(raw.rsplit(marker, 1)[-1].split("]", 1)[0])
        except (ValueError, TypeError):
            rc = -1
    else:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            if raw.startswith("[local timeout after") or raw.startswith("[local error]"):
                rc = -1
        else:
            if isinstance(parsed, dict) and "error" in parsed:
                rc = -1
    return rc, raw


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
    client_class: str = "unknown",
    output_file_factory: Callable[[str], Path] | None = None,
    output_holder: list[Path | None] | None = None,
    task_id: str | None = None,
    expected_runtime: int | None = None,
) -> str:
    """Run execute_fn with adaptive blocking.

    Semantics of block_timeout:
      > 0  -- wait this many seconds inline, then auto-promote
      == 0 -- dispatch immediately (never block)
      < 0  -- block forever (legacy behaviour, no promotion)
    """
    task_id = task_id or secrets.token_hex(8)
    started_at = datetime.now(timezone.utc)
    output_file = output_file_factory(task_id) if output_file_factory else None
    if output_holder is not None:
        output_holder[0] = output_file

    _record_ledger_entry(
        task_id=task_id,
        agent=agent,
        host=host,
        prompt=prompt,
        client_class=client_class,
        dispatched_at=started_at,
        output_file=output_file,
    )

    work_task = asyncio.create_task(execute_fn())

    if block_timeout < 0:
        try:
            result = await work_task
        except asyncio.CancelledError:
            _complete_ledger_entry(
                task_id=task_id,
                status="failed",
                result_json=None,
                output_file=output_file,
                completed_at=datetime.now(timezone.utc),
            )
            raise
        except Exception:
            _complete_ledger_entry(
                task_id=task_id,
                status="failed",
                result_json=None,
                output_file=output_file,
                completed_at=datetime.now(timezone.utc),
            )
            raise
        _complete_ledger_entry(
            task_id=task_id,
            status="done",
            result_json=result,
            output_file=output_file,
            completed_at=datetime.now(timezone.utc),
        )
        return result

    if block_timeout > 0:
        try:
            result = await asyncio.wait_for(
                asyncio.shield(work_task),
                timeout=block_timeout,
            )
            _complete_ledger_entry(
                task_id=task_id,
                status="done",
                result_json=result,
                output_file=output_file,
                completed_at=datetime.now(timezone.utc),
            )
            return result
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            _complete_ledger_entry(
                task_id=task_id,
                status="failed",
                result_json=None,
                output_file=output_file,
                completed_at=datetime.now(timezone.utc),
            )
            raise
        except Exception:
            _complete_ledger_entry(
                task_id=task_id,
                status="failed",
                result_json=None,
                output_file=output_file,
                completed_at=datetime.now(timezone.utc),
            )
            raise

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
            _complete_ledger_entry(
                task_id=task_id,
                status=ts.status,
                result_json=ts.result_json,
                output_file=ts.output_file,
                completed_at=ts.finished_at,
            )
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


def register_orchestra_tools(mcp: object, config: MaestroConfig) -> None:
    """Register orchestra tools on the given FastMCP instance."""
    global _CONFIG
    _CONFIG = config

    from mcp.server.fastmcp import FastMCP

    assert isinstance(mcp, FastMCP)

    @mcp.tool()
    async def codex(
        host: str, prompt: str, working_dir: str,
        model: str = "", reasoning_effort: str = "xhigh", timeout: int = 0,
    ) -> str:
        """Dispatch a coding task to Codex CLI. Requires explicit working_dir (validated against host's allowed_dirs).

        Handles: scope prefix injection, CLI flag construction, output capture to disk, task ledger recording, auto-promote to background. Default timeout: 1800s. Returns inline result or {auto_promoted: true, task_id} — use poll() for status, read_output() for full results."""
        try:
            cfg = _resolve_host_config(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({"error": "validation_error", "host": host, "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}"})
        ctx = get_client_context()
        effective_timeout = timeout if timeout > 0 else config.codex_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        output_holder: list[Path | None] = [None]

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file is not None
            model_flag = f"--model {shlex.quote(model)} " if model else ""
            effort_flag = f"-c model_reasoning_effort={shlex.quote(reasoning_effort)} "
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            cli_cmd = f"codex exec --dangerously-bypass-approvals-and-sandbox --json {model_flag}{effort_flag}-C {shlex.quote(working_dir)} {escaped_prompt}"
            task_label = output_file.stem.rsplit("_", 1)[-1][:8]
            window_name = f"codex-{task_label}"
            logger.info("Orchestra: codex on %s [%s]: %s...", host, task_label, prompt[:80])
            rc, raw_output = await _orchestra_run_cli(
                host,
                cli_cmd,
                timeout=effective_timeout,
                cwd=working_dir,
                window_name=window_name,
            )
            return _orchestra_build_result("codex", host, prompt, raw_output, rc, output_file)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="codex",
            host=host,
            prompt=prompt,
            client_class=ctx.classification,
            output_file_factory=lambda tid: _orchestra_output_path("codex", tid),
            output_holder=output_holder,
        )

    @mcp.tool()
    async def gemini(
        host: str, prompt: str, working_dir: str,
        context_files: list[str] | None = None, model: str = "",
        approval_mode: str = "plan", resume: str = "", timeout: int = 0,
    ) -> str:
        """Dispatch an analysis/research task to Gemini CLI. Exploits 1M-token context. Returns task_id — use poll() for results. Prefer over exec().

        approval_mode: "plan" (read-only), "yolo" (auto-approve all), "auto_edit" (auto-approve edits), "default" (prompt).
        resume: Session index (e.g. "1") or "latest" to continue a previous chat.
        WARNING: Resuming a session re-sends the entire history, costing tokens for all previous turns.
        """
        try:
            cfg = _resolve_host_config(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({"error": "validation_error", "host": host, "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}"})
        ctx = get_client_context()
        effective_timeout = timeout if timeout > 0 else config.gemini_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        output_holder: list[Path | None] = [None]

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file is not None
            full_prompt = prompt
            if context_files:
                file_refs = " ".join(f"@{f}" for f in context_files)
                full_prompt = f"{file_refs} {prompt}"

            model_flag = f"--model {shlex.quote(model)} " if model else ""
            approval_flag = f"--approval-mode {shlex.quote(approval_mode)} "
            resume_flag = f"--resume {shlex.quote(resume)} " if resume else ""

            cli_cmd = (
                f"gemini -p {shlex.quote(full_prompt)} --output-format json "
                f"{model_flag}{approval_flag}{resume_flag}"
            )

            task_label = output_file.stem.rsplit("_", 1)[-1][:8]
            window_name = f"gemini-{task_label}"
            logger.info("Orchestra: gemini on %s [%s]: %s...", host, task_label, prompt[:80])
            rc, raw_output = await _orchestra_run_cli(
                host,
                cli_cmd,
                timeout=effective_timeout,
                cwd=working_dir,
                window_name=window_name,
            )
            return _orchestra_build_result("gemini", host, prompt, _extract_gemini_response(raw_output), rc, output_file)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="gemini",
            host=host,
            prompt=prompt,
            client_class=ctx.classification,
            output_file_factory=lambda tid: _orchestra_output_path("gemini", tid),
            output_holder=output_holder,
        )

    @mcp.tool()
    async def read_output(file_path: str, start_line: int = 0, max_lines: int = 200) -> str:
        """Read full or partial output from a previous agent run. Restricted to files in the orchestra output directory.

        Use start_line and max_lines for windowed reads to control context cost. Returns total_lines and has_more for pagination."""
        fp = Path(file_path)
        try:
            fp.resolve().relative_to(config.orchestra_output_dir.resolve())
        except ValueError:
            return json.dumps({"error": f"Access denied: only files in {config.orchestra_output_dir}"})
        if not fp.exists():
            return json.dumps({"error": f"File not found: {file_path}"})
        lines = fp.read_text(encoding="utf-8").splitlines()
        total = len(lines)
        selected = lines[start_line : start_line + max_lines]
        return json.dumps({
            "file": str(fp),
            "total_lines": total,
            "start_line": start_line,
            "lines_returned": len(selected),
            "has_more": start_line + max_lines < total,
            "content": "\n".join(selected),
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    async def claude(
        host: str, prompt: str, working_dir: str,
        allowed_tools: str = "Edit,Write,Bash(git:*),Bash(python:*),Bash(python3:*),Bash(pip:*),Bash(cat:*),Bash(grep:*),Bash(head:*),Bash(tail:*),Bash(ls:*),Bash(find:*),Bash(mkdir:*),Bash(cp:*),Bash(sed:*),Bash(wc:*),Bash(echo:*),Bash(diff:*),Bash(timeout:*),Read", timeout: int = 0,
    ) -> str:
        """Dispatch a coding task to Claude Code CLI. Requires explicit working_dir (validated against host's allowed_dirs).

        Handles: scope prefix injection, --permission-mode bypassPermissions, allowed_tools whitelist, output capture, task ledger, auto-promote. Default timeout: 1200s. Returns inline result or {auto_promoted: true, task_id} — use poll() for status, read_output() for full results."""
        try:
            cfg = _resolve_host_config(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({"error": "validation_error", "host": host, "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}"})
        ctx = get_client_context()
        effective_timeout = timeout if timeout > 0 else config.claude_timeout
        block_timeout = ctx.profile["block_timeout_agent"]
        output_holder: list[Path | None] = [None]

        async def _execute() -> str:
            output_file = output_holder[0]
            assert output_file is not None
            scoped_prompt = AGENT_SCOPE_PREFIX + prompt
            escaped_prompt = shlex.quote(scoped_prompt)
            escaped_tools = shlex.quote(allowed_tools)
            cli_cmd = (
                f"claude -p {escaped_prompt} --output-format json "
                f"--permission-mode bypassPermissions "
                f"--allowedTools {escaped_tools}"
            )
            task_label = output_file.stem.rsplit("_", 1)[-1][:8]
            window_name = f"claude-{task_label}"
            logger.info("Orchestra: claude on %s [%s]: %s...", host, task_label, prompt[:80])
            rc, raw_output = await _orchestra_run_cli(
                host,
                cli_cmd,
                timeout=effective_timeout,
                cwd=working_dir,
                window_name=window_name,
            )
            return _orchestra_build_result("claude", host, prompt, raw_output, rc, output_file)

        return await _auto_promote(
            _execute,
            block_timeout=block_timeout,
            agent="claude",
            host=host,
            prompt=prompt,
            client_class=ctx.classification,
            output_file_factory=lambda tid: _orchestra_output_path("claude", tid),
            output_holder=output_holder,
        )

    @mcp.tool()
    async def prepare_relay() -> str:
        """Get an ephemeral bearer token for the HTTP transfer relay and task result endpoints. Valid for 1 hour. Use with: curl -H "Authorization: Bearer <token>" on /transfer/push, /transfer/pull, /tasks/{id}/result."""
        import secrets as _s
        from maestro.relay import register_ephemeral_token as _reg

        value = _s.token_urlsafe(32)
        _reg(value, ttl=3600)
        return json.dumps({"value": value, "ttl_seconds": 3600})

    @mcp.tool()
    async def tasks(
        status: str | None = None,
        agent: str | None = None,
        host: str | None = None,
        last: int = 10,
    ) -> str:
        """List recent tasks from the persistent ledger. Filters: status (running|done|failed|timeout|orphaned), agent (codex|claude|gemini|exec|script), host. Returns up to `last` entries sorted most-recent-first with relative timestamps.

        Survives Maestro restarts. Tasks older than 30 days are auto-pruned."""
        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})
        now = datetime.now(timezone.utc)
        rows = [
            {
                "task_id": entry.task_id,
                "agent": entry.agent,
                "host": entry.host,
                "status": entry.status,
                "dispatched_at": _format_relative_time(entry.dispatched_at, now),
                "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
                "return_code": entry.return_code,
                "output_file": entry.output_file,
                "result_url": entry.result_url,
            }
            for entry in ledger.query(status=status, agent=agent, host=host, last=last)
        ]
        return json.dumps({"tasks": rows}, ensure_ascii=False)

    @mcp.tool()
    async def poll(task_id: str) -> str:
        """Check task status in the persistent ledger. Returns metadata only: task_id, agent, host, status, timestamps, return_code, output_file, result_url.

        Does NOT return result payloads. For full output: use read_output(output_file) for targeted line ranges, or curl the result_url (from prepare_relay) for zero-context retrieval."""
        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})
        entry = ledger.get(task_id)
        if entry is None:
            return json.dumps({"error": f"Task '{task_id}' not found"})
        result: dict[str, Any] = {
            "task_id": entry.task_id,
            "agent": entry.agent,
            "host": entry.host,
            "status": entry.status,
            "dispatched_at": entry.dispatched_at.isoformat(),
            "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
            "return_code": entry.return_code,
            "output_file": entry.output_file,
            "result_url": entry.result_url,
        }
        if entry.status == "running":
            elapsed = (datetime.now(timezone.utc) - entry.dispatched_at).total_seconds()
            result["elapsed_seconds"] = round(elapsed, 1)
        return json.dumps(result, ensure_ascii=False)
