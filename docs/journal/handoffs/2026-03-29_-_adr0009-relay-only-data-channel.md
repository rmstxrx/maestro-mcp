# Handoff — 2026-03-29 — ADR-0009: Relay-Only Data Channel

**Session scope:** Architecture design, implementation (Phases 1–3), deployment, and validation of the relay-only data channel for Maestro MCP.

---

## What Was Done

### ADR-0009 Authored and Accepted
- **Core principle:** The exec channel is a pure control channel. The HTTP relay is the sole data channel. No exceptions.
- **Lifecycle:** generate → push (relay) → exec (trigger) → observe/pull (relay) → reason locally
- **Tool surface:** 13 → 9 tools
  - **Removed:** `run` (command param), `read`, `write`, `transfer`, `read_output`
  - **Added:** `exec` (staged-only trigger), `observe` (tmux pane capture), `steer` (keystrokes)
  - **Retained:** `stop`, `status`, `tasks`, `dispatch`, `service`, `prepare_relay`
- **ADR-0008 reversed:** `observe` and `steer` reinstated as control-plane tools
- File: `docs/adr/ADR-0009_-_relay-only-data-channel.md`

### Phases 1–3 Implemented by Codex Spark (xhigh, ~3 min)
- **mux.py:** Added `STAGING_INBOX`/`STAGING_OUTBOX`, `_build_staged_wrapper()`. Kept `_build_wrapper()` for dispatch compatibility (Phase 4). `create_task_window()` now accepts `staged: bool`.
- **relay.py:** Added `_is_maestro_path()` whitelist for `/tmp/maestro/` on all hosts.
- **fleet.py:** `run` → `exec` (no `command` param, `task_id` required). Deleted `read`/`write`/`transfer`. Added `observe`/`steer`.
- **orchestra.py:** Deleted `read_output`. Restored `poll` for compat.
- **Tests:** 60 passed, 7 skipped (legacy mux wrapper tests).
- Commit: `33a0f76` on main.

### Deployed to Cellar
- `git pull` + `docker compose build --no-cache` + `docker compose up -d`
- Cloudflared unaffected (bare metal)
- Tool cache required MCP connector disconnect/reconnect

### End-to-End Validated
- Full lifecycle tested: script generated in container, relay-pushed to `/tmp/maestro/inbox/`, `exec` triggered, results relay-pulled from `/tmp/maestro/outbox/`, read locally. Zero escaping, zero blocking.

---

## Key Architectural Insights

1. **Exec is an interrupt line, relay is the data bus.** The MCP tool channel should never carry payload — only control signals. This is ADR-0002's filesystem-as-protocol principle applied to the Claude↔host boundary.

2. **Observe and steer are control-plane, not data transport.** They carry ~50 lines / a few keystrokes. Essential for supervising dispatched agents. Removing them was an error (corrected mid-session after Claude was put through the pain of observing Codex without them).

3. **The 5-second auto-promote window was the problem, not a feature.** Current SSE client `block_timeout_exec: 5` means any task >5s returns only task_id anyway. ADR-0009 makes this universal — `exec` always returns immediately (`block_timeout=0`).

4. **Script reuse amortizes cost.** Push once, exec many. Relay token lasts 1 hour. Amortized cost per task: 1 MCP call + 2 container-local bash steps.

5. **Tmux was never the problem.** The input/output channels were. Tmux stays as execution wrapper; what changed is that it only receives a fixed template pointing to a staged file.

---

## What Remains

### Phase 4: Dispatch Adaptation
- `dispatch` still uses old `_build_wrapper()` path (inline CLI command construction)
- Should be adapted to: write agent CLI as script → relay-push to inbox → exec via staged template
- This eliminates the last remaining inline command construction
- `service` should follow the same adaptation

### Phase 5: Cleanup
- Delete `_build_wrapper()` and `_build_script_wrapper()` from `mux.py` once dispatch is migrated
- Remove `_build_script_wrapper` (already deleted by Codex)
- Clean up `_remote_preamble()` powershell paths if no longer needed
- Update CLAUDE.md, AGENTS.md with new tool surface
- Update Claude.ai connector tool descriptions

### Output Directory Consolidation
- Current mess: `~/.maestro/task_output/` (hub tee), `~/.maestro/outputs/` (orchestra), `/tmp/maestro/outbox/` (ADR-0009)
- Proposed: `/tmp/maestro/outbox/<id>.out` on target host = canonical output location
- Hub-local directories become internal implementation details
- Should be addressed alongside Phase 4

### AGENTS.md Commit Guard
- Rômulo noted that AGENTS.md prevents agents from committing/pushing — correctly so (an agent once opened and merged a PR autonomously)
- This session's commit was done via `run` tool by Claude (strategist), not a dispatched agent
- The guard is appropriate for dispatched agents; no changes needed

### Pending Non-Maestro Tasks
- GPQA Diamond benchmark on hybrid FP8 Qwen3.5-122B-A10B (~8h job)
- TurboQuant: weight fusion (bake rotation Π into W_Q/W_K/W_V/W_O)
- SOAR 2026: MiniCPM-SALA quantization/speculative decoding paths

---

## Fleet State

| Host | Status | Notes |
|------|--------|-------|
| Apollyon | Connected | Maestro dev repo at `~/Development/maestro-mcp`, commit `33a0f76` |
| Cellar | Connected | Deployed, running ADR-0009 Phase 1–3 code |
| Eden | Connected | |
| Eden-WSL | Connected | |
| Judas | Offline | |
