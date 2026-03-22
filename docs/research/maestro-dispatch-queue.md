# Maestro v2 — Dispatch Queue

Sequential phases. Fire each one AFTER the previous commit lands.
All use: `codex_dispatch(host="apollyon", model="gpt-5.3-codex-spark", timeout=1800, working_dir="/home/rmstxrx/Development/maestro-mcp")`

---

## Phase C — Orchestra Extraction + Execute/Dispatch Merge
**Prereq:** Phase B committed

```
Read journal/2026-03-07-adr-0003-maestro-v2.md for context. The worktree is clean. Proceed without asking questions.

TASK: Implement Phase C — Orchestra Extraction + Execute/Dispatch Merge.

1. Create maestro/tools/orchestra.py containing:
   - TaskState dataclass (currently ~1328-1339)
   - TASK_REGISTRY, _REGISTRY_LOCK globals
   - _evict_stale_tasks(), _periodic_eviction()
   - _orchestra_output_dir(), _orchestra_output_path(), _orchestra_task_id()
   - _orchestra_truncate(), _extract_gemini_response(), _orchestra_build_result()
   - _orchestra_run_cli_raw(), _orchestra_run_cli()
   - _auto_promote()
   - AGENT_SCOPE_PREFIX constant

2. Create maestro/tools/__init__.py (empty)

3. Merge execute/dispatch pairs in server.py — the dispatch variants are 3-line wrappers that just call execute with block_timeout=0. Since block_timeout will be server-decided:
   - Remove codex_dispatch (keep codex_execute, rename to codex_execute)
   - Remove gemini_dispatch (keep gemini_analyze as the single entry point, add mode= parameter: "analyze" default, "execute" for --yolo, "research" for search grounding)
   - Remove claude_dispatch (keep claude_execute)
   - Remove gemini_execute (fold into gemini_analyze with mode="execute")
   - Remove gemini_research (fold into gemini_analyze with mode="research")
   - This reduces 8 agent tools to 3: codex_execute, gemini_analyze, claude_execute

4. Remove maestro_bg and maestro_bg_log — they're subsumed by auto-promote on exec/script.

5. Remove max_budget_usd parameter from claude_execute and claude_dispatch. Remove --max-budget-usd from the CLI command string.

6. Update server.py to import orchestra components from maestro.tools.orchestra.

7. Commit as "feat(phase-c): extract orchestra, merge dispatch pairs, remove bg tools"

8. Run: .venv/bin/pytest tests/test_primitives.py -q

CONSTRAINTS: Do NOT touch maestro_oauth.py, oauth_rewrite.py, or tests/. Do NOT rename the remaining tools yet (that's Phase F). Do NOT extract fleet tools (exec, script, read, write) — they stay in server.py for now.
```

---

## Phase D — Relay Extraction
**Prereq:** Phase B committed

```
Read journal/2026-03-07-adr-0003-maestro-v2.md for context. The worktree is clean. Proceed without asking questions.

TASK: Implement Phase D — Relay Extraction.

1. Create maestro/relay.py containing:
   - _validate_transfer_path() (currently ~689-729)
   - _transfer_auth_ok() (~732-739)
   - _auth_error() (~742-747)
   - _transfer_push() (~751-822)
   - _transfer_pull() (~826-891)
   - All transfer constants: _TRANSFER_TOKEN, _MAX_TRANSFER_SIZE, _TRANSFER_ALLOWED_DIRS, _SYSTEM_DIRS

2. The relay module should import what it needs from maestro.config.
   - It needs access to _resolve_host, _scp_run, _local_host_hint (or their equivalents from transport/local modules).
   - Use function parameters or explicit imports — no circular dependencies.

3. Update server.py:
   - Import and register the relay routes from maestro.relay
   - Remove the inline relay code from server.py

4. Commit as "feat(phase-d): extract transfer relay to maestro/relay.py"

5. Run: .venv/bin/pytest tests/test_primitives.py -q

CONSTRAINTS: Do NOT touch maestro_oauth.py, oauth_rewrite.py, tests/, or MCP tool functions.
```

---

## Phase G — Client-Aware Unification
**Prereq:** Phase C committed

```
Read journal/2026-03-07-adr-0003-maestro-v2.md for context (Part III: Client-Aware Unification). The worktree is clean. Proceed without asking questions.

TASK: Implement Phase G — Client Classification + Per-Client Profiles.

1. Create maestro/client.py containing:

   a. CLIENT_PROFILES dict with "remote", "local", "lan" profiles as specified in ADR section 3.3

   b. ClientContext dataclass:
      - classification: str
      - profile: dict
      - client_id: str | None = None

   c. _client_ctx ContextVar[ClientContext]

   d. _classify_client(request: Request) -> str:
      - Check for CF-Ray header → "remote" (came through Cloudflare)
      - Check client IP is localhost → "local" (Claude Code on Apollyon)
      - Check client IP starts with "10.42.69." → "lan"
      - Default → "remote" (safe: treat unknown as constrained)

   e. set_client_context(request: Request) function that creates ClientContext and sets the contextvar

   f. get_client_context() -> ClientContext helper

2. In server.py, add ASGI middleware (in _MaestroMiddleware or a new one) that calls set_client_context() for every HTTP request.

3. Update _auto_promote to read block_timeout from the client profile instead of accepting it as a parameter:
   - ctx = get_client_context()
   - block_timeout = ctx.profile["block_timeout_agent"] for agent tools
   - block_timeout = ctx.profile["block_timeout_exec"] for exec/script

4. Update agent_poll:
   - Remove wait parameter
   - Add poll cooldown: read ctx.profile["poll_cooldown"], track last_polled_at on TaskState, reject premature polls with {"status": "cooldown", "retry_after": N}
   - Bypass cooldown for completed tasks

5. Remove block_timeout parameter from all tool function signatures (maestro_exec, maestro_script, codex_execute, gemini_analyze, claude_execute).

6. Remove timeout parameter from all client-facing tool signatures. Use CONFIG values internally.

7. Remove wait parameter from agent_poll signature.

8. Commit as "feat(phase-g): client-aware profiles, poll cooldown, remove client-facing timeout params"

9. Run: .venv/bin/pytest tests/test_primitives.py -q

CONSTRAINTS: Do NOT touch maestro_oauth.py, oauth_rewrite.py, or tests/. Do NOT rename tools.
```

---

## Phase E — Slim Entry Point
**Prereq:** Phases B, C, D all committed

```
Read journal/2026-03-07-adr-0003-maestro-v2.md for context. The worktree is clean. Proceed without asking questions.

TASK: Implement Phase E — Slim Entry Point.

1. Create maestro/tools/fleet.py containing the remaining MCP tool functions:
   - maestro_exec, maestro_script, maestro_read, maestro_write
   - maestro_upload, maestro_download, maestro_status
   - agent_status, agent_read_output

2. Move _format_result, _ps_quote, _wrap_command, _resolve_host, _local_host_hint, _update_host_status into appropriate existing modules (hosts.py or transport.py).

3. Move HostConfig, HostShell, HostStatus, _load_hosts to maestro/hosts.py.

4. Reduce server.py to entry-point wiring only:
   - Import modules
   - Create FastMCP instance
   - Register tools from fleet and orchestra
   - Register relay routes
   - argparse + uvicorn startup
   - Target: ~100-150 lines

5. Commit as "feat(phase-e): slim entry point, extract fleet tools and host registry"

6. Run: .venv/bin/pytest tests/test_primitives.py -q (update imports in test if needed — this is the one exception where you MAY update test imports to point to new module locations, but do NOT change test logic)

CONSTRAINTS: Do NOT touch maestro_oauth.py or oauth_rewrite.py. Do NOT rename tools yet. You MAY update test import paths.
```

---

## Phase F — Tool Consolidation + Schema Compression
**Prereq:** Phase E committed

```
Read journal/2026-03-07-adr-0003-maestro-v2.md for context (section 2.2). The worktree is clean. Proceed without asking questions.

TASK: Implement Phase F — Tool Consolidation + Schema Compression.

1. Drop maestro_ prefix from all fleet tools:
   - maestro_exec → exec
   - maestro_script → script
   - maestro_read → read
   - maestro_write → write
   - maestro_upload + maestro_download → transfer (single tool with direction= parameter)
   - maestro_status → status

2. Rename agent tools:
   - codex_execute → codex
   - gemini_analyze → gemini
   - claude_execute → claude
   - agent_poll → poll
   - agent_read_output → read_output
   - agent_status → agent_status (keep as-is)

3. Compress ALL tool docstrings to one-liners. Move detailed docs to a TOOLS.md reference file. Examples:
   - exec: "Run a command on a host."
   - script: "Run a multi-line script on a host."
   - codex: "Dispatch task to Codex CLI. Returns task_id."
   - poll: "Check task status or retrieve result."

4. Update maestro_status to return structured JSON instead of ASCII art:
   {"hosts": {"apollyon": {"status": "connected", "local": true}, ...}, "available": N, "total": N}

5. Commit as "feat(phase-f): consolidate tools 20→10, compress docstrings, structured status"

6. Run: .venv/bin/pytest tests/test_primitives.py -q (update test imports if needed)

CONSTRAINTS: Do NOT touch maestro_oauth.py or oauth_rewrite.py. You MAY update test imports. Create TOOLS.md with the detailed documentation removed from docstrings.
```
