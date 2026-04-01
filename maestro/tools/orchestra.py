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
# Agent catalog — single source of truth for dispatch validation
# ---------------------------------------------------------------------------

AGENT_CATALOG: dict[str, dict] = {
    "codex": {
        "models": {
            "gpt-5.4":             "Flagship reasoning, 1M ctx. Complex multi-file, architectural.",
            "gpt-5.4-mini":        "Faster, cost-effective reasoning. Medium complexity.",
            "gpt-5.4-nano":        "Fastest, cheapest. Simple well-defined tasks only.",
            "gpt-5.3-codex":       "Advanced coding. Standard implementation tasks.",
            "gpt-5.3-codex-spark": "Blazing fast. ONLY tightly-scoped single-file tasks.",
        },
        "default_model": "gpt-5.3-codex",
        "has_effort": True,
        "valid_efforts": {"low", "medium", "high", "xhigh"},
        "default_effort": "xhigh",
        "role": "Implementation. Code writing, refactoring, diffs, bug fixes.",
    },
    "gemini": {
        "models": {
            "gemini-3.1-pro-preview": "Deep research, thorough review, complex analysis.",
            "gemini-3-flash-preview":  "Quick review, summaries, simple research.",
        },
        "default_model": "gemini-3.1-pro-preview",
        "has_effort": False,
        "role": (
            "Reviewer and researcher. Google search, 1M context. "
            "NEVER for writing production code."
        ),
    },
    "claude": {
        "models": {},
        "default_model": None,
        "has_effort": False,
        "role": (
            "Architectural judgment. Ambiguous cross-domain tasks, whole-project "
            "reasoning. Credits compete with orchestrator — use sparingly."
        ),
    },
}

ALL_VALID_MODELS: set[str] = {
    m for cat in AGENT_CATALOG.values() for m in cat.get("models", {})
}


def _validate_dispatch_args(
    agent: str, model: str, reasoning_effort: str,
) -> tuple[str, str, list[str]]:
    """Validate and resolve dispatch arguments against the catalog.

    Returns (resolved_model, resolved_effort, warnings).
    Raises ValueError on hard validation failures.
    """
    if agent not in AGENT_CATALOG:
        raise ValueError(
            f"agent must be one of {list(AGENT_CATALOG)}, got '{agent}'"
        )

    cat = AGENT_CATALOG[agent]
    warnings: list[str] = []

    # --- Model resolution ---
    if model:
        valid_models = cat.get("models", {})
        if not valid_models:
            warnings.append(
                f"Agent '{agent}' ignores --model (passed '{model}'). Proceeding without it."
            )
            model = ""
        elif model not in valid_models:
            raise ValueError(
                f"Invalid model '{model}' for agent '{agent}'. "
                f"Valid: {list(valid_models)}"
            )
    else:
        model = cat.get("default_model") or ""

    # --- Effort resolution ---
    if cat.get("has_effort"):
        valid_efforts = cat["valid_efforts"]
        if reasoning_effort:
            if reasoning_effort not in valid_efforts:
                raise ValueError(
                    f"Invalid reasoning_effort '{reasoning_effort}' for agent '{agent}'. "
                    f"Valid: {sorted(valid_efforts)}"
                )
        else:
            reasoning_effort = cat["default_effort"]
    else:
        if reasoning_effort:
            warnings.append(
                f"Agent '{agent}' has no effort toggle (passed '{reasoning_effort}'). Ignored."
            )
        reasoning_effort = ""

    return model, reasoning_effort, warnings


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
    stale = []
    async with _REGISTRY_LOCK:
        stale = [
            tid for tid, ts in TASK_REGISTRY.items()
            if ts.finished_at and (now - ts.finished_at).total_seconds() > cfg.task_eviction_seconds
        ]
        for tid in stale:
            ts = TASK_REGISTRY.pop(tid)
            if ts.asyncio_task and not ts.asyncio_task.done():
                ts.asyncio_task.cancel()

    pruned_output_files = 0
    output_dir = _task_output_dir()
    if output_dir.exists():
        cutoff = now - timedelta(days=cfg.output_retention_days)
        for path in output_dir.iterdir():
            if not path.is_file():
                continue
            try:
                modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if modified_at >= cutoff:
                continue
            try:
                path.unlink()
                pruned_output_files += 1
            except OSError:
                pass

    if stale:
        logger.info(f"Orchestra: evicted {len(stale)} stale tasks from registry")
        _save_registry()
    if pruned_output_files:
        logger.info(
            "Orchestra: pruned %d task_output files older than %d days",
            pruned_output_files,
            cfg.output_retention_days,
        )


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

def _task_output_dir() -> Path:
    from maestro.mux import get_output_dir

    return get_output_dir()


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
) -> tuple[int, str]:
    """Run a CLI command on a host, returning (rc, formatted_output).

    Uses the SSH transport layer directly (ADR-0007)."""
    from maestro.hosts import HostShell

    assert _FORMAT_RESULT and _ASYNC_RUN and _RESOLVE_HOST

    cfg = _RESOLVE_HOST(host)
    if cfg.shell == HostShell.POWERSHELL:
        rc, stdout, stderr = await _orchestra_run_cli_raw_ps(host, cli_command, timeout, cwd)
        return rc, _FORMAT_RESULT(stdout, stderr, rc)

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
    task_type: str = "",
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
        task_type=task_type,
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
            if ts.status != "killed":
                ts.status = "done"
                ts.result_json = result
        except asyncio.CancelledError:
            if ts.status != "killed":
                ts.status = "failed"
                ts.result_json = json.dumps({
                    "error": "cancelled", "task_id": task_id, "agent": agent,
                })
        except Exception as exc:
            if ts.status != "killed":
                logger.exception(f"auto_promote [{task_id}] {agent} on {host} failed")
                ts.status = "failed"
                ts.result_json = json.dumps({
                    "error": str(exc), "task_id": task_id, "agent": agent,
                })
        finally:
            if ts.status == "killed" and ts.result_json is None:
                ts.result_json = json.dumps({
                    "task_id": task_id,
                    "agent": agent,
                    "host": host,
                    "status": "killed",
                })
            ts.finished_at = ts.finished_at or datetime.now(timezone.utc)
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
        reasoning_effort: str = "",
        approval_mode: str = "plan",
        context_files: list[str] | None = None,
        resume: str = "",
        allowed_tools: str = "",
    ) -> str:
        """Build the CLI command string for a given agent.

        Expects model and reasoning_effort to be already resolved
        by _validate_dispatch_args (catalog defaults applied, invalid
        values rejected).
        """
        scoped_prompt = AGENT_SCOPE_PREFIX + prompt
        escaped_prompt = shlex.quote(scoped_prompt)

        if agent == "codex":
            model_flag = f"--model {shlex.quote(model)} " if model else ""
            effort_flag = (
                f"-c model_reasoning_effort={shlex.quote(reasoning_effort)} "
                if reasoning_effort else ""
            )
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
            # plan requires interactive TTY; force yolo for headless dispatch
            effective_approval = "yolo" if approval_mode == "plan" else approval_mode
            approval_flag = f"--approval-mode {shlex.quote(effective_approval)} "
            resume_flag = f"--resume {shlex.quote(resume)} " if resume else ""
            return (
                f"gemini -p {escaped} --output-format json "
                f"{model_flag}{approval_flag}{resume_flag}"
                f"< /dev/null"  # stdin EOF: prevents readStdin() hang in non-TTY
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
    async def dispatch_agent(
        host: str,
        agent: str,
        prompt: str,
        working_dir: str,
        expected_runtime: int | None = None,
        model: str = "",
        reasoning_effort: str = "",
        approval_mode: str = "plan",
        context_files: list[str] | None = None,
        resume: str = "",
        allowed_tools: str = "",
    ) -> str:
        """Dispatch a task to an AI agent (codex, gemini, or claude).

        AGENT SELECTION GUIDE — read before every call:

          codex  — Implementation. Code writing, refactoring, diffs, bug fixes.
                   Models: gpt-5.4 (flagship 1M ctx), gpt-5.4-mini (faster),
                   gpt-5.4-nano (cheapest), gpt-5.3-codex (standard coding),
                   gpt-5.3-codex-spark (blazing fast, ONLY well-scoped tasks).
                   Default: gpt-5.3-codex @ xhigh effort.
                   Effort: low | medium | high | xhigh.

          gemini — Reviewer/researcher. Google search, 1M context window.
                   NEVER for writing production code.
                   Models: gemini-3.1-pro-preview (deep work),
                           gemini-3-flash-preview (quick work).
                   Default: gemini-3.1-pro-preview. No effort flag.

          claude — Architectural judgment. Ambiguous cross-domain tasks needing
                   whole-project understanding. Credits compete with orchestrator.
                   No model or effort flags. Use sparingly.

        TASK ROUTING — before calling dispatch, ask:
          • Is this a simple file read, ls, cat, or grep? → Use run_task, not dispatch_agent.
          • Is this code implementation? → codex.
          • Is this review, research, or reading a large file? → gemini.
          • Is this ambiguous and cross-domain? → claude.

        Returns {auto_promoted: true, task_id}. Use current_tasks() for status.
        Timeout: 6h hard ceiling (system policy).
        expected_runtime: your honest estimate (seconds). Recorded verbatim.
        Validates model and reasoning_effort against the agent catalog."""
        # --- Validate agent, model, effort against catalog (fail fast) ---
        try:
            resolved_model, resolved_effort, val_warnings = _validate_dispatch_args(
                agent, model, reasoning_effort,
            )
        except ValueError as e:
            return json.dumps({"error": "validation_error", "detail": str(e)})

        # --- Validate host + working_dir ---
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
        from maestro.hosts import HostShell

        ctx = get_client_context()
        task_id = secrets.token_hex(8)
        ert = expected_runtime if expected_runtime is not None else config.default_expected_runtime_dispatch
        host_cfg = _resolve_host(host)

        cli_cmd = _build_agent_cli(
            agent, prompt, working_dir,
            model=resolved_model, reasoning_effort=resolved_effort,
            approval_mode=approval_mode, context_files=context_files,
            resume=resume, allowed_tools=allowed_tools,
        )

        async def _execute() -> str:
            script_content = f"#!/bin/bash\n{cli_cmd}\n"
            await stage_script(task_id, host_cfg.alias, script_content, host_cfg.shell)
            output_file = await create_task_window(
                task_id,
                host_cfg.alias,
                tee=True,
                cwd=working_dir,
                stream=True,
                shell=host_cfg.shell,
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
            return _orchestra_build_result(
                agent=agent,
                host=host,
                prompt=prompt,
                raw_output=raw_output,
                return_code=rc,
                output_file=out_path,
            )

        if host_cfg.shell == HostShell.POWERSHELL:
            val_warnings.append(
                f"Host '{host}' uses PowerShell. Agent dispatches (codex/gemini/claude) "
                "use bash-based wrappers that may fail. Consider dispatching to a "
                "bash-compatible host (e.g., eden-wsl instead of eden)."
            )

        result = await _auto_promote(
            _execute,
            block_timeout=0,  # dispatches always go background
            agent=agent,
            host=host,
            prompt=prompt[:200],
            client_class=ctx.classification,
            task_id=task_id,
            expected_runtime=ert,
            output_file_factory=get_output_path,
            task_type="dispatch",
        )

        if not val_warnings:
            return result

        payload = json.loads(result)
        payload["warnings"] = val_warnings
        return json.dumps(payload)

    @mcp.tool()
    async def prepare_relay() -> str:
        """Get an ephemeral bearer token for direct relay or task-result HTTP calls.

        Rarely needed: transfer_pull_file and transfer_push_file prepare auth
        automatically. Use this for direct /tasks/{id}/result polling or other
        custom relay workflows."""
        import secrets as _s
        from maestro.relay import register_ephemeral_token as _reg

        value = _s.token_urlsafe(32)
        _reg(value, ttl=3600)
        return json.dumps({"value": value, "ttl_seconds": 3600})

    @mcp.tool()
    async def transfer_pull_file(host: str, remote_path: str) -> str:
        """Stage a fleet file server-side and return a ready-to-run curl command."""
        from maestro.relay import transfer_pull_impl

        try:
            result = await transfer_pull_impl(host, remote_path)
        except FileNotFoundError as exc:
            return json.dumps({
                "error": "not_found",
                "host": host,
                "remote_path": remote_path,
                "detail": str(exc),
            })
        except ValueError as exc:
            return json.dumps({
                "error": "validation_error",
                "host": host,
                "remote_path": remote_path,
                "detail": str(exc),
            })
        except RuntimeError as exc:
            return json.dumps({
                "error": "transfer_failed",
                "host": host,
                "remote_path": remote_path,
                "detail": str(exc),
            })
        return json.dumps(result, ensure_ascii=False)

    @mcp.tool()
    async def transfer_push_file(host: str, remote_path: str) -> str:
        """Prepare an authenticated curl command for uploading a local file."""
        from maestro.relay import transfer_push_prep

        try:
            result = await transfer_push_prep(host, remote_path)
        except ValueError as exc:
            return json.dumps({
                "error": "validation_error",
                "host": host,
                "remote_path": remote_path,
                "detail": str(exc),
            })
        return json.dumps(result, ensure_ascii=False)

    @mcp.tool()
    async def current_tasks(
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
                "output_available": bool(entry.output_file and Path(entry.output_file).exists()),
                "output_hint": (
                    f"Use read_task_output('{entry.task_id}') to read."
                    if entry.output_file and Path(entry.output_file).exists()
                    else "No captured output available for this task."
                ),
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
    async def read_task_output(
        task_id: str,
        tail: int | None = None,
        head: int | None = None,
        full: bool = False,
    ) -> str:
        """Read or download captured task output by task ID."""
        if tail is not None and head is not None:
            return json.dumps({
                "error": "validation_error",
                "detail": "Provide tail or head, not both.",
                "task_id": task_id,
            })
        if full and (tail is not None or head is not None):
            return json.dumps({
                "error": "validation_error",
                "detail": "full=True cannot be combined with tail or head.",
                "task_id": task_id,
            })
        if tail is not None and tail <= 0:
            return json.dumps({
                "error": "validation_error",
                "detail": "tail must be > 0",
                "task_id": task_id,
            })
        if head is not None and head <= 0:
            return json.dumps({
                "error": "validation_error",
                "detail": "head must be > 0",
                "task_id": task_id,
            })

        ledger = get_task_ledger()
        if ledger is None:
            return json.dumps({"error": "Task ledger is not configured"})

        entry = ledger.get(task_id)
        if entry is None:
            return json.dumps({"error": "Task not found", "task_id": task_id})
        if not entry.output_file:
            return json.dumps({
                "error": "output_unavailable",
                "task_id": task_id,
                "status": entry.status,
                "detail": "No captured output is available for this task.",
            })

        output_path = Path(entry.output_file)
        if not output_path.exists():
            return json.dumps({
                "error": "output_unavailable",
                "task_id": task_id,
                "status": entry.status,
                "detail": "Captured output file not found.",
            })

        byte_count = output_path.stat().st_size

        if full:
            from maestro.hosts import _local_host_name
            from maestro.relay import transfer_pull_impl

            local_host = _local_host_name()
            if not local_host:
                return json.dumps({
                    "error": "not_configured",
                    "task_id": task_id,
                    "detail": "No local host is configured for staged downloads.",
                })
            result = await transfer_pull_impl(local_host, str(output_path))
            return json.dumps({
                "task_id": task_id,
                "status": entry.status,
                "bytes": result["bytes"],
                "curl": result["curl"],
            }, ensure_ascii=False)

        content = output_path.read_text(encoding="utf-8", errors="replace")
        base: dict[str, Any] = {
            "task_id": task_id,
            "status": entry.status,
        }

        if tail is not None or head is not None:
            lines = content.splitlines()
            requested = tail if tail is not None else head
            selected = lines[-requested:] if tail is not None else lines[:requested]
            base["lines_requested"] = requested
            base["content"] = "\n".join(selected)
            if entry.status == "running":
                base["bytes_so_far"] = byte_count
            return json.dumps(base, ensure_ascii=False)

        preview_limit = 2000
        base["bytes"] = byte_count
        base["content_preview"] = content[:preview_limit]
        base["truncated"] = len(content) > preview_limit
        base["hint"] = (
            "Use tail= or head= for targeted reads, or full=True to download the complete file."
        )
        if entry.status == "running":
            base["bytes_so_far"] = byte_count
        return json.dumps(base, ensure_ascii=False)
