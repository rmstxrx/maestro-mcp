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
    expected_runtime: int | None = None
    task_type: str = ""

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
            "expected_runtime": self.expected_runtime,
            "task_type": self.task_type,
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
            expected_runtime=data.get("expected_runtime"),
            task_type=data.get("task_type", ""),
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
    status: str = "running",
    client_class: str,
    dispatched_at: datetime,
    output_file: Path | None,
    expected_runtime: int | None = None,
    task_type: str = "",
) -> None:
    if _TASK_LEDGER is None:
        return
    _TASK_LEDGER.record(
        TaskLedgerEntry(
            task_id=task_id,
            agent=agent,
            host=host,
            prompt=prompt[:200],
            status=status,
            client_class=client_class,
            dispatched_at=dispatched_at,
            output_file=str(output_file) if output_file else None,
            expected_runtime=expected_runtime,
            task_type=task_type,
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
    cleanup: bool = False,
) -> tuple[int, str]:
    """Run a CLI command on a host, returning (rc, formatted_output).

    Uses the SSH transport layer directly (ADR-0007).
    The window_name parameter is accepted for signature compatibility
    but ignored — dispatch has its own tmux code path."""
    from maestro.hosts import HostShell

    assert _FORMAT_RESULT and _ASYNC_RUN and _RESOLVE_HOST

    cfg = _RESOLVE_HOST(host)
    if cfg.shell == HostShell.POWERSHELL:
        rc, stdout, stderr = await _orchestra_run_cli_raw_ps(host, cli_command, timeout, cwd)
        return rc, _FORMAT_RESULT(stdout, stderr, rc)

    if window_name:
        from maestro.mux import mux_spawn

        ssh_target = getattr(cfg, "alias", host)
        output = await mux_spawn(
            ssh_target,
            cli_command,
            window_name,
            timeout=timeout,
            cwd=cwd,
            sudo=False,
            cleanup=cleanup,
        )
        import re

        rc = 0
        match = re.search(r"\[exit code:\s*(-?\d+)\]\s*$", output)
        if match:
            rc = int(match.group(1))
        return rc, output

    full_cmd = _WRAP_COMMAND(cfg, cli_command, cwd, False)
    rc, stdout, stderr = await _ASYNC_RUN(["ssh", cfg.alias, full_cmd], timeout=timeout)
    return rc, _FORMAT_RESULT(stdout, stderr, rc)


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
        expected_runtime=expected_runtime,
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

    # --- ADR-0007: Unified dispatch ---

    def _build_agent_cli(
        agent: str,
        prompt: str,
        working_dir: str,
        *,
        model: str = "",
        reasoning_effort: str = "xhigh",
        approval_mode: str = "plan",
        context_files: list[str] | None = None,
        resume: str = "",
        allowed_tools: str = "",
    ) -> str:
        """Build the CLI command string for a given agent."""
        # One-shot: full CLI with scoped prompt
        scoped_prompt = AGENT_SCOPE_PREFIX + prompt
        escaped_prompt = shlex.quote(scoped_prompt)

        if agent == "codex":
            model_flag = f"--model {shlex.quote(model)} " if model else ""
            effort_flag = f"-c model_reasoning_effort={shlex.quote(reasoning_effort)} "
            return (
                f"codex exec --dangerously-bypass-approvals-and-sandbox --json "
                f"{model_flag}{effort_flag}"
                f"-C {shlex.quote(working_dir)} {escaped_prompt}"
            )
        elif agent == "gemini":
            full_prompt = prompt
            if context_files:
                file_refs = " ".join(f"@{f}" for f in context_files)
                full_prompt = f"{file_refs} {prompt}"
            escaped = shlex.quote(AGENT_SCOPE_PREFIX + full_prompt)
            model_flag = f"--model {shlex.quote(model)} " if model else ""
            approval_flag = f"--approval-mode {shlex.quote(approval_mode)} "
            resume_flag = f"--resume {shlex.quote(resume)} " if resume else ""
            return (
                f"gemini -p {escaped} --output-format json "
                f"{model_flag}{approval_flag}{resume_flag}"
            )
        elif agent == "claude":
            default_tools = (
                "Edit,Write,Bash(git:*),Bash(python:*),Bash(python3:*),Bash(pip:*),"
                "Bash(cat:*),Bash(grep:*),Bash(head:*),Bash(tail:*),Bash(ls:*),"
                "Bash(find:*),Bash(mkdir:*),Bash(cp:*),Bash(sed:*),Bash(wc:*),"
                "Bash(echo:*),Bash(diff:*),Bash(timeout:*),Read"
            )
            tools = allowed_tools or default_tools
            return (
                f"claude -p {escaped_prompt} --output-format json "
                f"--permission-mode bypassPermissions "
                f"--allowedTools {shlex.quote(tools)}"
            )
        else:
            raise ValueError(f"Unknown agent: {agent}")

    @mcp.tool()
    async def dispatch(
        host: str,
        agent: str,
        prompt: str,
        working_dir: str,
        expected_runtime: int | None = None,
        model: str = "",
        reasoning_effort: str = "xhigh",
        approval_mode: str = "plan",
        context_files: list[str] | None = None,
        resume: str = "",
        allowed_tools: str = "",
    ) -> str:
        """Dispatch a task to an AI agent (codex, gemini, or claude).

        All dispatches run in the background (block_timeout=0). Returns
        {auto_promoted: true, task_id}. Use tasks() for status,
        read_output(file_path) for completion output.

        Timeout: 6h hard ceiling (system policy). 30min default overtime flag.
        expected_runtime: your estimate (seconds). Recorded verbatim in ledger.

        Validates working_dir against host's allowed_dirs.
        Injects AGENT_SCOPE_PREFIX (pointer to AGENTS.md) automatically."""
        valid_agents = ("codex", "gemini", "claude")
        if agent not in valid_agents:
            return json.dumps({"error": "validation_error", "detail": f"agent must be one of {valid_agents}, got '{agent}'"})
        try:
            cfg = _resolve_host_config(host)
        except ValueError as e:
            return _structured_error("validation_error", host, str(e))
        if cfg.allowed_dirs and not any(working_dir.startswith(d) for d in cfg.allowed_dirs):
            return json.dumps({
                "error": "validation_error", "host": host,
                "detail": f"working_dir '{working_dir}' not in allowed_dirs: {cfg.allowed_dirs}",
            })

        from maestro.mux import create_task_window, wait_for_completion, get_output_path, stage_script
        from maestro.hosts import _resolve_host

        ctx = get_client_context()
        task_id = secrets.token_hex(8)
        ert = expected_runtime if expected_runtime is not None else config.default_expected_runtime_dispatch
        host_cfg = _resolve_host(host)

        cli_cmd = _build_agent_cli(
            agent, prompt, working_dir,
            model=model, reasoning_effort=reasoning_effort,
            approval_mode=approval_mode, context_files=context_files,
            resume=resume, allowed_tools=allowed_tools,
        )

        async def _execute() -> str:
            script_content = f"#!/bin/bash\n{cli_cmd}\n"
            await stage_script(task_id, host_cfg.alias, script_content)
            output_file = await create_task_window(
                task_id,
                host_cfg.alias,
                tee=True,
                interactive=False,
                cwd=working_dir,
                staged=True,
                stream=True,
            )
            rc = await wait_for_completion(task_id, timeout=config.dispatch_ceiling)

            # Read captured output
            raw_output = ""
            out_path = get_output_path(task_id)
            if out_path.exists():
                raw_output = out_path.read_text(encoding="utf-8", errors="replace")

            # Post-process gemini JSON envelope
            if agent == "gemini":
                raw_output = _extract_gemini_response(raw_output)

            # Build structured result
            preview, was_truncated = _orchestra_truncate(raw_output)
            return json.dumps({
                "agent": agent,
                "host": host,
                "success": rc == 0,
                "return_code": rc,
                "output_file": str(out_path),
                "output_preview": preview,
                "truncated": was_truncated,
                "output_bytes": len(raw_output),
            }, indent=2, ensure_ascii=False)

        return await _auto_promote(
            _execute,
            block_timeout=0,  # dispatches always go background
            agent=agent,
            host=host,
            prompt=prompt[:200],
            client_class=ctx.classification,
            task_id=task_id,
            expected_runtime=ert,
            output_file_factory=lambda tid: _orchestra_output_path(agent, tid),
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
        task_type: str | None = None,
        last: int = 10,
    ) -> str:
        """List recent tasks from the persistent ledger (ADR-0007).

        Filters: status (running|done|failed|timeout|orphaned|killed),
        agent (codex|claude|gemini|exec|script), host, task_type (run|dispatch|service).
        Returns up to `last` entries sorted most-recent-first.

        Running tasks include elapsed_seconds and an overtime flag when
        elapsed exceeds the caller's declared expected_runtime.

        Survives Maestro restarts. Tasks older than 30 days are auto-pruned."""
        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})
        now = datetime.now(timezone.utc)
        entries = ledger.query(status=status, agent=agent, host=host, last=last)
        if task_type is not None:
            entries = [e for e in entries if e.task_type == task_type]
        rows = []
        for entry in entries:
            row: dict[str, Any] = {
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
            if entry.task_type:
                row["task_type"] = entry.task_type
            if entry.status == "running":
                elapsed = (now - entry.dispatched_at).total_seconds()
                row["elapsed_seconds"] = round(elapsed, 1)
                if entry.expected_runtime is not None:
                    row["expected_runtime"] = entry.expected_runtime
                    row["overtime"] = elapsed > entry.expected_runtime
            rows.append(row)
        return json.dumps({"tasks": rows}, ensure_ascii=False)

    @mcp.tool()
    async def poll(task_id: str) -> str:
        """Poll a specific task for latest status."""
        from maestro.tools.orchestra import get_task_ledger

        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})

        entry = ledger.get(task_id)
        if entry is None:
            return json.dumps({"error": "Task not found", "task_id": task_id})

        result = {
            "task_id": entry.task_id,
            "agent": entry.agent,
            "host": entry.host,
            "status": entry.status,
            "prompt": entry.prompt,
            "dispatched_at": entry.dispatched_at.isoformat(),
            "completed_at": entry.completed_at.isoformat() if entry.completed_at else None,
            "return_code": entry.return_code,
            "output_file": entry.output_file,
            "result_url": entry.result_url,
        }

        if entry.status == "running":
            result["elapsed_seconds"] = round(
                (datetime.now(timezone.utc) - entry.dispatched_at).total_seconds(),
                1,
            )
        return json.dumps(result)
