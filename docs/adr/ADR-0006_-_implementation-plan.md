# ADR-0006 Implementation Plan

**Target branch:** `feat/adr-0006-task-ledger`  
**Base:** `main` (after housekeeping commit)

## Phase order

Changes are ordered to minimize risk and allow incremental testing.

---

### Phase 1: Relay TTL bump (trivial, instant win)

**File:** `maestro/tools/fleet.py`

1. In `prepare_relay()`, change `_reg(v, ttl=300)` → `_reg(v, ttl=3600)`
2. Update the return message: `"ttl_seconds": 3600`
3. Update the docstring: "valid for 1 hour"

**Test:** Call `prepare_relay`, verify returned TTL. Verify token works
after 6 minutes (would have expired under old TTL).

---

### Phase 2: TaskLedger class

**File:** `maestro/tools/orchestra.py` (new class alongside `TaskRegistryStore`)

1. Define `TaskLedgerEntry` dataclass:
   ```python
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
   ```

2. Define `TaskLedger` class:
   - `__init__(self, path: Path, issuer_url: str)` — path to JSON file,
     issuer URL for constructing result URLs
   - `record(self, entry: TaskLedgerEntry)` — upsert by task_id
   - `update(self, task_id: str, **fields)` — partial update (status,
     completed_at, return_code)
   - `query(self, *, status, agent, host, last) -> list[TaskLedgerEntry]`
     — filtered retrieval
   - `get(self, task_id: str) -> TaskLedgerEntry | None` — single lookup
   - `_save()` / `_load()` — atomic JSON persistence (same pattern as
     `OAuthStateStore`)
   - `_prune(self, max_age_days: int = 30)` — remove entries older than
     threshold

3. Integration points in `_auto_promote()`:
   - After generating `task_id`, create a `TaskLedgerEntry` and call
     `ledger.record(entry)`
   - In the `_monitor()` closure, after setting final status, call
     `ledger.update(task_id, status=..., completed_at=..., return_code=...)`

4. Add `client_class` to the record:
   - In `_auto_promote`, accept an optional `client_class: str` kwarg
   - Callers (dispatch tools in `fleet.py`) pass
     `get_client_context().classification`

**File:** `maestro/config.py`

5. Add `task_ledger_path: Path` field to `MaestroConfig`, defaulting to
   `~/.maestro/task_ledger.json`. Env var: `MAESTRO_TASK_LEDGER_PATH`.

**File:** `server.py`

6. Instantiate `TaskLedger` and pass into `configure_orchestra()`.

**Test:** Dispatch a task, verify ledger file is created and contains
the entry. Let task complete, verify status update. Restart Maestro,
verify ledger survives.

---

### Phase 3: `tasks` tool

**File:** `maestro/tools/fleet.py`

1. Register `tasks` tool:
   ```python
   @mcp.tool()
   async def tasks(
       status: str | None = None,
       agent: str | None = None,
       host: str | None = None,
       last: int = 10,
   ) -> str:
       """List recent tasks from the task ledger."""
   ```

2. Delegates to `TaskLedger.query()`, formats as compact JSON table.

3. Each row includes: `task_id`, `agent`, `host`, `status`, `dispatched_at`
   (as relative time like "12m ago"), `completed_at`, `return_code`,
   `output_file`, `result_url`.

**Test:** Dispatch 3 tasks to different agents, call `tasks()`, verify
all appear. Filter by `agent="codex"`, verify only Codex tasks returned.

---

### Phase 4: `poll` rewrite (status-only)

**File:** `maestro/tools/fleet.py`

1. Rewrite `poll` to return ledger metadata only:
   - Look up task in ledger (not just registry)
   - Return: task_id, agent, host, status, dispatched_at, completed_at,
     return_code, output_file, result_url
   - If task is running, include `elapsed_seconds`
   - **Never** return `result_json` through MCP

2. Remove the `wait` parameter entirely.

3. Remove `_inject_poll_verification` function — no longer needed since
   `poll` never returns result payloads.

4. Remove the cooldown logic — `poll` is now a lightweight metadata read,
   not a result-delivery mechanism. Cooldowns were protecting against
   context burn from repeated result fetches; metadata-only responses
   are cheap.

5. Update tool docstring to direct callers to HTTP endpoint or
   `read_output` for full results.

**Test:** Dispatch a task, call `poll` before and after completion. Verify
response contains metadata but not the full output. Verify `result_url`
is a working HTTPS URL.

---

### Phase 5: Dispatch guard

**File:** `maestro/tools/fleet.py`

1. Add `_AGENT_CLI_PATTERNS` regex:
   ```python
   _AGENT_CLI_PATTERNS = re.compile(
       r'\b(codex|gemini|claude)\b.*(-[pq]|--prompt|--model|--message)',
       re.IGNORECASE,
   )
   ```

2. Add `_check_agent_dispatch_bypass(command: str) -> str | None` function.

3. Call at entry of `exec` and `script`, after `_check_local_self_reference`:
   ```python
   if block := _check_agent_dispatch_bypass(command):
       return block
   ```

4. The error response includes:
   - Which agent was detected
   - Which dispatch tool to use instead
   - Why (scope prefix, ledger tracking, correct arguments)

**Test:**
- `exec(command="codex -q --model o4-mini -p 'fix bug'")` → blocked
- `exec(command="codex --version")` → allowed
- `exec(command="which gemini")` → allowed
- `exec(command="gemini -p 'analyze this'")` → blocked
- `exec(command="claude --model sonnet -p 'review code'")` → blocked

---

### Phase 6: Documentation updates

1. **CLAUDE.md** — add `tasks` tool to the tool list, document the
   background watcher pattern, note that `poll` is status-only.

2. **STATE.md** — update to reflect ADR-0006 implementation.

3. **TODO.md** — item 3 (cross-reference HTTP alternatives) is partially
   addressed by the `poll` rewrite. Update status.

4. **ADR-0006** status — change from "Proposed" to "Accepted" once
   implementation begins.

5. **ADR-0005** status — change from "Proposed" to "Implemented" (overdue
   from last session).

---

## Commit strategy

| Commit | Content |
|---|---|
| 1 | Phase 1: relay TTL bump |
| 2 | Phase 2 + 3: TaskLedger class + `tasks` tool |
| 3 | Phase 4: `poll` rewrite |
| 4 | Phase 5: dispatch guard |
| 5 | Phase 6: doc updates |

Each commit should leave tests passing. Commits 2–4 can be squashed into
one if preferred before merge.

## Open questions

1. **Ledger pruning** — automatic (background loop like eviction) or
   manual only? Leaning toward manual for now; 30 days of task metadata
   is tiny (< 1MB even at heavy use).

2. **`tasks` tool output format** — compact JSON array, or something more
   human-readable? Leaning toward JSON since the LLM will parse it, but
   could add a `format="table"` option later.

3. **Ledger in the HTTP task_result endpoint** — should `/tasks/{id}/result`
   fall back to the ledger if the task has been evicted from TASK_REGISTRY?
   This would make the HTTP endpoint work for historical tasks too. Leaning
   yes, but it's a Phase 2+ enhancement (the ledger doesn't store
   `result_json`, only the `output_file` path — so the endpoint would
   need to read the file).
